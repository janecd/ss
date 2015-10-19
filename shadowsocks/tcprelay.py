#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, with_statement

import time
import sys
import socket
import errno
import struct
import os
import json
# from shadowsocks.common import logging
import traceback
import random
import logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import encrypt, eventloop, shell, common
from shadowsocks.common import parse_header

# logging = sys.modules['logging']

# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

MSG_FASTOPEN = 0x20000000

# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

# for each opening port, we have a TCP Relay

# for each connection, we have a TCP Relay Handler to handle the connection

# for each handler, we have 2 sockets:
#   local:   connected to the client
#   remote:  connected to remote server

# for each handler, it could be at one of several stages:

# as sslocal:
# stage 0 SOCKS hello received from local, send hello to local
# stage 1 addr received from local, query DNS for remote
# stage 2 UDP assoc
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

# as ssserver:
# stage 0 just jump to stage 1
# stage 1 addr received from local, query DNS for remote
# stage 3 DNS resolved, connect to remote
# stage 4 still connecting, more data from local received
# stage 5 remote connected, piping local and remote

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1

# for each handler, we have 2 stream directions:
#   upstream:    from client to server direction
#          read local and write to remote
#   downstream:  from server to client direction
#          read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 32 * 1024
log_str_buf = []


class TCPRelayHandler(object):

    def __init__(self, server, fd_to_handlers, loop, local_sock, config, dns_resolver, is_local):
        logging.debug("Running in the TCPRelayHandler class. [__init__]")
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock
        self._remote_sock = None
        self._config = config
        self._dns_resolver = dns_resolver

        # TCP Relay works as either sslocal or ssserver
        # if is_local, this is sslocal
        self._is_local = is_local
        self._stage = STAGE_INIT
        self._encryptor = encrypt.Encryptor(
            config['password'], config['method'])
        self._fastopen_connected = False
        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []
        self._upstream_status = WAIT_STATUS_READING
        self._downstream_status = WAIT_STATUS_INIT
        self._client_address = local_sock.getpeername()[:2]
        self._remote_address = None
        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']
        else:
            self._forbidden_iplist = None
        if is_local:
            self._chosen_server = self._get_a_server()
        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        loop.add(
            local_sock, eventloop.POLL_IN | eventloop.POLL_ERR, self._server)
        self.last_activity = 0
        self._update_activity()

    def __hash__(self):
        # default __hash__ is id / 16
        # we want to eliminate collisions
        return id(self)

    @property
    def remote_address(self):
        return self._remote_address

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if type(server_port) == list:
            server_port = random.choice(server_port)
        if type(server) == list:
            server = random.choice(server)
        # self._config["password"] = str(self._config["port_password"]["%s" % server_port]).strip()
        # logging.debug('chosen server: %s:%d   with password:%s', server, server_port,self._config["password"])
#         server_port = random.choice([1990, 1991, 1992, 1993, 443, 5445, 4224, 7010, 8002, 9001, 5351, 20720, 29920, 31337, 17788, 6566, 6001, 13724, 8888, 22347, 47808])
#         server = random.choice(["45.78.2.150","52.74.245.100","58.96.176.16"])
        return server, server_port

    def _update_activity(self, data_len=0):
        logging.debug("Running in the TCPRelayHandler class. [_update_activity]")
        # tell the TCP Relay we have activities recently
        # else it will think we are inactive and timed out
        self._server.update_activity(self, data_len)

    def _update_stream(self, stream, status):
        logging.debug("Running in the TCPRelayHandler class. [_update_stream]")
        # update a stream to a new waiting status

        # check if status is changed
        # only update if dirty
        dirty = False
        if stream == STREAM_DOWN:
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True
        if dirty:
            if self._local_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                if self._upstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                self._loop.modify(self._local_sock, event)
            if self._remote_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                if self._upstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                self._loop.modify(self._remote_sock, event)

    def _write_to_sock(self, data, sock):
        logging.debug("Running in the TCPRelayHandler class. [_write_to_sock]")
        # write data to sock
        # if only some of the data are written, put remaining in the buffer
        # and update the stream to wait for writing
        if not data or not sock:
            return False
        uncomplete = False
        try:
            l = len(data)
            if sock == self._local_sock and self._is_local and self._stage == STAGE_INIT:
                logging.info("[Client] Received data from browser and just sending 'hello' back to [browser] ! data length is: [%s]" % l)
            elif sock == self._remote_sock and self._is_local and self._stage == STAGE_STREAM:
                logging.info("[Client] Received data from browser and just sending -encrypted- data to [VPS] ! data length is: [%s]" % l)
            elif sock == self._local_sock and self._is_local and self._stage == STAGE_STREAM:
                logging.info("[Client] Received data from VPS and just sending -decrypted- data to [browser] ! data length is: [%s]" % l)
            elif sock == self._remote_sock and not self._is_local and self._stage == STAGE_STREAM:
                logging.info("[Server] Received data from client and going to send -decrypted- data to [INTERNET] ! data length is: [%s]" % l)
            elif sock == self._local_sock and not self._is_local and self._stage == STAGE_STREAM:
                logging.info("[Server] Received data from INTERNET and going to send -encrypted- data to [client] ! data length is: [%s]" % l)
            if not self._is_local:
                if self._config.has_key('port_limit') and self._config['port_limit'] != "" and os.path.exists(self._config['port_limit']):
                    port_limits = json.loads(open(self._config['port_limit']).read())
                    if str(self._server._listen_port) in port_limits:
                        port_limits['%s' % self._server._listen_port]['used'] = port_limits['%s' % self._server._listen_port]['used'] + len(data)
                        open('%s' % self._config['port_limit'],"w").write("%s" % json.dumps(port_limits,indent=4,ensure_ascii=False,sort_keys=True))
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS, errno.EWOULDBLOCK):
                uncomplete = True
            else:
                shell.print_exception(e)
                self.destroy()
                return False
        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN, WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            else:
                logging.error('write_all_to_sock:unknown socket')
                common.error_to_file('write_all_to_sock:unknown socket',self._config)
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP, WAIT_STATUS_READING)
            else:
                logging.error('write_all_to_sock:unknown socket')
                common.error_to_file('write_all_to_sock:unknown socket',self._config)
        return True

    def _handle_stage_connecting(self, data):
        logging.debug("Running in the TCPRelayHandler class. [_handle_stage_connecting]")
        if self._is_local:
            data = self._encryptor.encrypt(data)
        self._data_to_write_to_remote.append(data)
        if self._is_local and not self._fastopen_connected and self._config['fast_open']:
            # for sslocal and fastopen, we basically wait for data and use
            # sendto to connect
            try:
                # only connect once
                self._fastopen_connected = True
                remote_sock = self._create_remote_socket(
                    self._chosen_server[0], self._chosen_server[1])
                self._loop.add(remote_sock, eventloop.POLL_ERR, self._server)
                data = b''.join(self._data_to_write_to_remote)
                l = len(data)
                s = remote_sock.sendto(data, MSG_FASTOPEN, self._chosen_server)
                if s < l:
                    data = data[s:]
                    self._data_to_write_to_remote = [data]
                else:
                    self._data_to_write_to_remote = []
                self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                    # in this case data is not sent at all
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                elif eventloop.errno_from_exception(e) == errno.ENOTCONN:
                    logging.error('fast open not supported on this OS')
                    common.error_to_file('fast open not supported on this OS',self._config)
                    self._config['fast_open'] = False
                    self.destroy()
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
                    self.destroy()

    def _handle_stage_addr(self, data):
        logging.debug("Running in the TCPRelayHandler class. [_handle_stage_addr]")
        try:
            if self._is_local:
                cmd = common.ord(data[1])
                if cmd == CMD_UDP_ASSOCIATE:
                    logging.debug('UDP associate')
                    if self._local_sock.family == socket.AF_INET6:
                        header = b'\x05\x00\x00\x04'
                    else:
                        header = b'\x05\x00\x00\x01'
                    addr, port = self._local_sock.getsockname()[:2]
                    addr_to_send = socket.inet_pton(
                        self._local_sock.family, addr)
                    port_to_send = struct.pack('>H', port)
                    self._write_to_sock(
                        header + addr_to_send + port_to_send, self._local_sock)
                    self._stage = STAGE_UDP_ASSOC
                    # just wait for the client to disconnect
                    return
                elif cmd == CMD_CONNECT:
                    # just trim VER CMD RSV
                    data = data[3:]
                else:
                    logging.error('unknown command %d' % cmd)
                    common.error_to_file('unknown command %d' % cmd,self._config)
                    self.destroy()
                    return
            header_result = parse_header(data,self._config)
            if header_result is None:
                raise Exception('can not parse header')
            addrtype, remote_addr, remote_port, header_length = header_result
            logging.info('connecting %s:%d from %s:%d' % (common.to_str(
                remote_addr), remote_port, self._client_address[0], self._client_address[1]))
            if self._server._listen_port in self._config['forbid']['port']:
                for i in self._config['forbid']['site']:
                    if str(i) in common.to_str(remote_addr):
                        self.destroy()
            try:
                if common.to_str(self._config['log']['log_enable']) == "True":
                    log_str_one_line = '''[%s]\t%s:%d\t%s:%d [server_port: %s]\n''' % (time.strftime(
                        "%Y-%m-%d %H:%M:%S"), common.to_str(remote_addr), remote_port, self._client_address[0], self._client_address[1],self._server._listen_port)
                    log_str_buf.append(log_str_one_line)
                    if os.path.exists(os.path.split(self._config['log']['log_path'])[0]) is False:
                        os.makedirs(os.path.split(self._config['log']['log_path'])[0])
                    if len(log_str_buf) == 10:
                        f = open("%s" % self._config['log']['log_path'], 'a+')
                        f.write("".join(log_str_buf))
                        f.close()
                        del log_str_buf[:]
            except Exception as e:
                logging.error(
                    "Sorry.Some ERROR happend when I try to log something to file : info: %s" % str(e))
                common.error_to_file("Sorry.Some ERROR happend when I try to log something to file : info: %s" % str(e),self._config)
            self._remote_address = (common.to_str(remote_addr), remote_port)
            # pause reading
            self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            self._stage = STAGE_DNS
            if self._is_local:
                # forward address to remote
                self._write_to_sock(
                    (b'\x05\x00\x00\x01' b'\x00\x00\x00\x00\x10\x10'), self._local_sock)
                data_to_send = self._encryptor.encrypt(data)
                self._data_to_write_to_remote.append(data_to_send)
                # notice here may go into _handle_dns_resolved directly
                self._dns_resolver.resolve(
                    self._chosen_server[0], self._handle_dns_resolved)
            else:
                if len(data) > header_length:
                    self._data_to_write_to_remote.append(data[header_length:])
                # notice here may go into _handle_dns_resolved directly
                self._dns_resolver.resolve(
                    remote_addr, self._handle_dns_resolved)
        except Exception as e:
            self._log_error(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _create_remote_socket(self, ip, port):
        logging.debug("Running in the TCPRelayHandler class. [_create_remote_socket]")
        addrs = socket.getaddrinfo(
            ip, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]
        if self._forbidden_iplist:
            if common.to_str(sa[0]) in self._forbidden_iplist:
                raise Exception(
                    'IP %s is in forbidden list, reject' % common.to_str(sa[0]))
        remote_sock = socket.socket(af, socktype, proto)
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock

    def _handle_dns_resolved(self, result, error):
        logging.debug("Running in the TCPRelayHandler class. [_handle_dns_resolved]")
        if error:
            self._log_error(error)
            self.destroy()
            return
        if result:
            ip = result[1]
            if ip:

                try:
                    self._stage = STAGE_CONNECTING
                    remote_addr = ip
                    if self._is_local:
                        remote_port = self._chosen_server[1]
                    else:
                        remote_port = self._remote_address[1]

                    if self._is_local and self._config['fast_open']:
                        # for fastopen:
                        # wait for more data to arrive and send them in one SYN
                        self._stage = STAGE_CONNECTING
                        # we don't have to wait for remote since it's not
                        # created
                        self._update_stream(STREAM_UP, WAIT_STATUS_READING)
                        # TODO when there is already data in this packet
                    else:
                        # else do connect
                        remote_sock = self._create_remote_socket(
                            remote_addr, remote_port)
                        try:
                            if self._is_local:
                                logging.info("[Client] I am just openning one port to connect VPS.")
                            elif not self._is_local:
                                logging.info("[Server] I am just openning one port to connect INTERNET.")
                            remote_sock.connect((remote_addr, remote_port))
                        except (OSError, IOError) as e:
                            if eventloop.errno_from_exception(e) == errno.EINPROGRESS:
                                pass
                        self._loop.add(
                            remote_sock, eventloop.POLL_ERR | eventloop.POLL_OUT, self._server)
                        self._stage = STAGE_CONNECTING
                        self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                        self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)
                    return
                except Exception as e:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        self.destroy()

    def _on_local_read(self):
        logging.debug("Running in the TCPRelayHandler class. [_on_local_read]")
        # handle all local read events and dispatch them to methods for
        # each stage
        if not self._local_sock:
            return
        is_local = self._is_local
        data = None
        try:
            data = self._local_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))
        if not is_local:
            data = self._encryptor.decrypt(data)
            if not data:
                return
#           if self._config.has_key('port_limit') and self._config['port_limit'] != "" and os.path.exists(self._config['port_limit']):
#               port_limits = json.loads(open(self._config['port_limit']).read())
#               if str(self._server._listen_port) in port_limits:
#                   port_limits['%s' % self._server._listen_port]['used'] = port_limits['%s' % self._server._listen_port]['used'] + len(data)
#                   open('%s' % self._config['port_limit'],"w").write("%s" % json.dumps(port_limits,indent=4,ensure_ascii=False,sort_keys=True))
        if self._stage == STAGE_STREAM:
            if self._is_local:
                data = self._encryptor.encrypt(data)
            self._write_to_sock(data, self._remote_sock)
            return
        elif is_local and self._stage == STAGE_INIT:
            # TODO check auth method
            self._write_to_sock(b'\x05\00', self._local_sock)
            self._stage = STAGE_ADDR
            return
        elif self._stage == STAGE_CONNECTING:
            self._handle_stage_connecting(data)
        elif (is_local and self._stage == STAGE_ADDR) or (not is_local and self._stage == STAGE_INIT):
            self._handle_stage_addr(data)

    def _on_remote_read(self):
        logging.debug("Running in the TCPRelayHandler class. [_on_remote_read]")
        # handle all remote read events
        data = None
        try:

            data = self._remote_sock.recv(BUF_SIZE)

        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))
        if self._is_local:
            data = self._encryptor.decrypt(data)
        else:
            data = self._encryptor.encrypt(data)
        try:
            self._write_to_sock(data, self._local_sock)
#             if not self._is_local:
#                 if self._config.has_key('port_limit') and self._config['port_limit'] != "" and os.path.exists(self._config['port_limit']):
#                     port_limits = json.loads(open(self._config['port_limit']).read())
#                     if str(self._server._listen_port) in port_limits:
#                         port_limits['%s' % self._server._listen_port]['used'] = port_limits['%s' % self._server._listen_port]['used'] + len(data) + BUF_SIZE
#                         open('%s' % self._config['port_limit'],"w").write("%s" % json.dumps(port_limits,indent=4,ensure_ascii=False,sort_keys=True))
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            # TODO use logging when debug completed
            self.destroy()

    def _on_local_write(self):
        logging.debug("Running in the TCPRelayHandler class. [_on_local_write]")
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
#           if not self._is_local:
#               if self._config.has_key('port_limit') and self._config['port_limit'] != "" and os.path.exists(self._config['port_limit']):
#                   port_limits = json.loads(open(self._config['port_limit']).read())
#                   if str(self._server._listen_port) in port_limits:
#                       port_limits['%s' % self._server._listen_port]['used'] = port_limits['%s' % self._server._listen_port]['used'] + len(data)
#                       open('%s' % self._config['port_limit'],"w").write("%s" % json.dumps(port_limits,indent=4,ensure_ascii=False,sort_keys=True))
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

    def _on_remote_write(self):
        logging.debug("Running in the TCPRelayHandler class. [_on_remote_write]")
        # handle remote writable event
        self._stage = STAGE_STREAM
        if self._data_to_write_to_remote:
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data, self._remote_sock)
#             if not self._is_local:
#                 if self._config.has_key('port_limit') and self._config['port_limit'] != "" and os.path.exists(self._config['port_limit']):
#                     port_limits = json.loads(open(self._config['port_limit']).read())
#                     if str(self._server._listen_port) in port_limits:
#                         port_limits['%s' % self._server._listen_port]['used'] = port_limits['%s' % self._server._listen_port]['used'] + len(data)
#                         open('%s' % self._config['port_limit'],"w").write("%s" % json.dumps(port_limits,indent=4,ensure_ascii=False,sort_keys=True))
        else:
            self._update_stream(STREAM_UP, WAIT_STATUS_READING)

    def _on_local_error(self):
        logging.debug("Running in the TCPRelayHandler class. [_on_local_error]")
        logging.warn('got local error')
        common.error_to_file('got local error',self._config)
        if self._local_sock:
            logging.error(eventloop.get_sock_error(self._local_sock))
            common.error_to_file(eventloop.get_sock_error(self._local_sock),self._config)
        self.destroy()

    def _on_remote_error(self):
        logging.debug("Running in the TCPRelayHandler class. [_on_remote_error]")
        logging.warn('got remote error')
        common.error_to_file('got remote error',self._config)
        if self._remote_sock:
            logging.error(eventloop.get_sock_error(self._remote_sock))
            common.error_to_file(eventloop.get_sock_error(self._remote_sock),self._config)
        self.destroy()

    def handle_event(self, sock, event):
        logging.debug("Running in the TCPRelayHandler class. [handle_event]")
        # handle all events in this handler and dispatch them to methods
        if self._stage == STAGE_DESTROYED:
            logging.debug('ignore handle_event: destroyed')
            return
        # order is important
        if sock == self._remote_sock:
            if event & eventloop.POLL_ERR:
                self._on_remote_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._local_sock:
            if event & eventloop.POLL_ERR:
                self._on_local_error()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_local_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_local_write()
        else:
            logging.warn('unknown socket')
            common.error_to_file('unknown socket',self._config)

    def _log_error(self, e):
        logging.error('%s when handling connection from %s:%d' % (
            common.to_str(e.message), self._client_address[0], self._client_address[1]))
        common.error_to_file('%s when handling connection from %s:%d' % (common.to_str(e.message), self._client_address[0], self._client_address[1]),self._config)

    def destroy(self):
        logging.debug("Running in the TCPRelayHandler class. [destory]")
        # destroy the handler and release any resources
        # promises:
        # 1. destroy won't make another destroy() call inside
        # 2. destroy releases resources so it prevents future call to destroy
        # 3. destroy won't raise any exceptions
        # if any of the promises are broken, it indicates a bug has been
        # introduced! mostly likely memory leaks, etc
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            logging.debug('destroy: %s:%d' % (self._remote_address))
        else:
            logging.debug('destroy')
        if self._remote_sock:
            logging.debug('destroying remote')
            self._loop.remove(self._remote_sock, self._server)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock, self._server)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)


class TCPRelay(object):

    def __init__(self, config, dns_resolver, is_local, stat_callback=None):
        logging.debug("Running in the TCPRelay class. [init]")
        self._config = config
        self._is_local = is_local
        self._dns_resolver = dns_resolver
        self._closed = False
        self._eventloop = None
        self._fd_to_handlers = {}

        self._timeout = config['timeout']
        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0  # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        if is_local:
            listen_addr = config['local_address']
            listen_port = config['local_port']
        else:
            listen_addr = config['server']
            listen_port = config['server_port']
        self._listen_port = listen_port

        addrs = socket.getaddrinfo(
            listen_addr, listen_port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (listen_addr, listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)
        if config['fast_open']:
            try:
                server_socket.setsockopt(socket.SOL_TCP, 23, 5)
            except socket.error:
                logging.error('warning: fast open is not available')
                common.error_to_file('warning: fast open is not available',self._config)

                self._config['fast_open'] = False
        server_socket.listen(1024)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    def add_to_loop(self, loop):
        logging.debug("Running in the TCPRelay class [add_to_loop]")
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        self._eventloop.add(
            self._server_socket, eventloop.POLL_IN | eventloop.POLL_ERR, self)
        self._eventloop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        logging.debug("Running in the TCPRelay class [remove_handler]")
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler, data_len):
        if data_len and self._stat_callback:
            self._stat_callback(self._listen_port, data_len)

        logging.debug("Running in the TCPRelay class [update_activity]")
        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        logging.debug("Running in the TCPRelay class  [_sweep_timeout]")
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            logging.debug("LOGGING sweeping timeouts")
            now = time.time()
            length = len(self._timeouts)
            # print("length of server._timeouts is: %s" % length)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler.remote_address:
                            logging.warn('timed out: %s:%d' %
                                         (handler.remote_address))
                            common.error_to_file('timed out: %s:%d' % (handler.remote_address),self._config)
                        else:
                            logging.warn('timed out some handler')
                            common.error_to_file('timed out some handler',self._config)
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def handle_event(self, sock, fd, event):
        logging.debug("Running in the TCPRelay class....[_handle_events]")
        # handle events and dispatch to handlers
        if sock:
            logging.debug("LOGGING fd %d %s" %
                          (fd, eventloop.EVENT_NAMES.get(event, event)))
        if not self._is_local:
            if self._config.has_key('port_limit') and self._config['port_limit'] != "" and os.path.exists(self._config['port_limit']):
                port_limits = json.loads(open(self._config['port_limit']).read())
                if str(self._listen_port) in port_limits and port_limits['%s' % self._listen_port]['used'] >= port_limits['%s' % self._listen_port]['total']:
                    logging.warn('[TCP] server listen port [%s] used traffic is over the setting value' % self._listen_port)
                    self.close()
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                # TODO
                raise Exception('server_socket error')
                common.error_to_file("server_socket error",self._config)
            try:
                logging.debug('accept')
                conn = self._server_socket.accept()
                TCPRelayHandler(self, self._fd_to_handlers,
                                self._eventloop, conn[0], self._config,
                                self._dns_resolver, self._is_local)
            except (OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, event)
            else:
                logging.warn('poll removed fd')
                common.error_to_file('poll removed fd',self._config)

    def handle_periodic(self):
        self._sweep_timeout()
        if self._closed:
            if self._server_socket:
                self._eventloop.remove(self._server_socket, self)
                self._eventloop.remove_periodic(self.handle_periodic)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed listen port %d' % self._listen_port)
            if not self._fd_to_handlers:
                self._eventloop.stop()

    def close(self, next_tick=False):
        logging.debug("Running in the TCPRelay class..[close]")
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket, self)
            self._server_socket.close()
            for handler in list(self._fd_to_handlers.values()):
                handler.destroy()

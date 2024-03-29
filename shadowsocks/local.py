#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function,  with_statement

import sys
import os
#from common import logging
import signal
import time
import random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
os.chdir(os.path.dirname(__file__))
import common
import logging

import shell, daemon, eventloop, tcprelay, udprelay, asyncdns
#from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, asyncdns


def main():

    shell.check_python()

    # fix py2exe
    if hasattr(sys, "frozen") and sys.frozen in  ("windows_exe", "console_exe"):
        p = os.path.dirname(os.path.abspath(sys.executable))
        os.chdir(p)

    config = shell.get_config(True)

    #added by tib for local random choose a server and the port and the port_password
    if config['port_password']:
        if config['password']:
            logging.warn('warning: port_password should not be used with server_port and password. server_port and password will be ignored')
#         config['server_port'] = int(random.choice(config['port_password'].items())[0])        
        if config.has_key('server_port'):
            if type(config['server_port']) == list and config['server_port']:
                config['server_port'] = random.choice(config.get('server_port', 8388))
            elif config['server_port']:
                config['server_port'] == int(common.to_str(config.get('server_port',8388)))
            else:
                config['server_port'] = int(random.choice(config['port_password'].items())[0])
        else:
            config['server_port'] = int(random.choice(config['port_password'].items())[0])
        config['password'] = common.to_str(config['port_password']["%s" % config['server_port']])
    else:
        if type(config['server_port']) == list and config['server_port']:
            config['server_port'] = random.choice(config.get('server_port', 8388))
        else:
            config['server_port'] == int(common.to_str(config.get('server_port',8388)))
        config["password"] = str(config["port_password"]["%s" % config["server_port"]]).strip()

    logging.warn('!' * 30)
    logging.info("OK.. I choose this guy to help me fuck the GFW.. [ %s : %s : %s : %s : %s]" % (config['server'],config['server_port'],config['password'],config['server_info']["%s" % config['server']],config['method']))
    logging.warn('!' * 30)
    time.sleep(1)

    daemon.daemon_exec(config)

    try:
        logging.info("starting local at %s:%d" % (config['local_address'], config['local_port']))

        dns_resolver = asyncdns.DNSResolver(config)
        tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
        udp_server = udprelay.UDPRelay(config, dns_resolver, True)
        loop = eventloop.EventLoop(config)
        dns_resolver.add_to_loop(loop)
        tcp_server.add_to_loop(loop)
        udp_server.add_to_loop(loop)

        def handler(signum, _):
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            tcp_server.close(next_tick=True)
            udp_server.close(next_tick=True)
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

        def int_handler(signum, _):
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        daemon.set_user(config.get('user', None))
        loop.run()
    except Exception as e:
        shell.print_exception(e)
        sys.exit(1)

if __name__ == '__main__':
    main()

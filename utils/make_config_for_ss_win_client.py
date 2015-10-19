#!/usr/bin/env python

import json,os,sys

if len(sys.argv) < 2:
	print "\nUsage:\n\t%s 'IP'" % sys.argv[0]
	sys.exit()

if os.path.exists('config.json') is not True:
	print "Sorry. No config.json found.. EXIT"
	sys.exit()

a = json.loads(open("config.json").read())

if a.has_key('method'):
	method = a['method']
else:
	method = "aes-256-cfb"

result = []

#for i in range(1,len(sys.argv)):
#	 for k,v in a.values()[0].items():
#		 #print k,v
#		 t_d = {}
#		 t_d['server'] = str(sys.argv[i])
#		 t_d['server_port'] = str(k)
#		 t_d['password'] = str(v)
#		 t_d['method'] = 'aes-256-cfb'
#		 t_d['remarks'] = '%s_%s' % (str(i),str(k))
#		 result.append(t_d)

#for i in sys.argv[1:]:
#	print i

for i in sys.argv[1:]:
	if a.has_key('port_password'):
		for k,v in a['port_password'].items():
			t_d = {}
			t_d['server'] = i
			t_d['server_port'] = str(k)
			t_d['password'] = str(v)
			t_d['method'] = method
			t_d['remarks'] = '[%s]_[%s]_[%s]' % (str(i),str(k),str(method))
			result.append(t_d)
		#print k,v

print json.dumps(result,indent=4)

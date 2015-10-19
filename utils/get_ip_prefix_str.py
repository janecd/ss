#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys,os

def Usage():
    print "Usage:\n\t%s IP [1-3]" % sys.argv[0]
    sys.exit()
    
if len(sys.argv) != 3:
    Usage()

if sys.argv[2] == "3":
    print "%s.%s.%s" % (sys.argv[1].split('.')[0],sys.argv[1].split('.')[1],sys.argv[1].split('.')[2])
elif sys.argv[2] == "2":
    print "%s.%s" % (sys.argv[1].split('.')[0],sys.argv[1].split('.')[1])
elif sys.argv[2] == "1":
    print "%s" % (sys.argv[1].split('.')[0])
else:
    print "ERROR"
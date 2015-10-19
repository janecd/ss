#!/bin/bash

#这个脚本的作用是取代添加更多的block china ip的规则

iptables_bin=$(which iptables)

if [ -z $iptables_bin ];then
	iptables_bin="/sbin/iptables"
fi

#echo -e "$iptables_bin"
N1=$($iptables_bin -L INPUT -vn|egrep policy|egrep DROP|wc -l)

if [ $N1 -ne 1 ];then
	$iptables_bin -P INPUT DROP
fi

N2=$($iptables_bin -L INPUT -vn|egrep ESTABLISHED|egrep ACCEPT|wc -l)
if [ $N2 -ne 1 ];then
	$iptables_bin -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

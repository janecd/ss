#!/bin/bash


iptables_bin=$(which iptables)
rules_store="/usr/local/DROP_ip_for_INPUT"

if [ ! -f $rules_store ];then
	touch $rules_store
fi

N=$($iptables_bin -L INPUT -vn|egrep -v "(pkt|Chain)"|egrep DROP|wc -l)
N2=$(cat $rules_store|wc -l)

if [ $N -ne $N2 ];then
	$iptables_bin -L INPUT -vn|egrep -v "(pkt|Chain)"|egrep DROP|awk '{print $8}' > $rules_store
fi



#!/bin/bash

if [ $# -ne 1 ];then
    echo -e "Usage:\n\t$0 \"IP\""
    exit 1
fi

ip="$1"

N=$(iptables -t filter -L INPUT -vn|egrep -w "$ip"|egrep "DROP"|wc -l)
if [ $N -ge 1 ];then
    echo -e "IP Address [ $ip ] Already Blocked..."
else
    iptables -t filter  -A INPUT -s $ip -j DROP
    if [ $? -eq 0 ];then
        echo -e "Blocked [ $ip ]"
    fi
fi

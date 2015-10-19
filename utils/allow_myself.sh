#!/bin/bash

[ -f "~/.bashrc" ] && . ~/.bashrc
iptables_bin=$(which iptables)


url="http://x.x.x.x:808/ip.html"

wget $url -O /tmp/ip.html >/dev/null 2>&1
if [ $? -ne 0 ];then
    echo -e "Maybe some error.. Network or apache on the server? Please Check it out ... :)"
    exit 1
fi

if [ $(cat /tmp/ip.html|wc -l) -eq 0 ];then
    echo -e "IP is empty And I will just EXIT"
    exit 1
fi       

while read line
do
    N=$($iptables_bin -t filter -L INPUT -vn|egrep -w "$line"|egrep "ACCEPT"|wc -l)
    if [ $N -ge 1 ];then
        echo -e "Already allowed IP $line"
    else
        echo -e "Added IP $line to allow"
        $iptables_bin -t filter -I INPUT -s $line -j ACCEPT
    fi
done < /tmp/ip.html
rm /tmp/ip.html 2>/dev/null
    

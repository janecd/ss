#!/bin/bash

log_path=""
all_china_ip_file_path=""
block_ip_tool=""

tmp_active_probe_ip="/tmp/today_active_probe_ip.txt"

if [ ! -f "$log_path" ];then
    echo -e "Sorry. No log file Found!!!"
    exit 1
fi
if [ ! -f "$all_china_ip_file_path" ];then
    echo -e "Sorry. No all_china_ip.txt Found!!!"
    exit 1
fi
if [ ! -f "$block_ip_tool" ];then
    echo -e "Sorry. No block_ip.sh Found!!!"
    exit 1
else
    chmod +x $block_ip_tool
fi


cat $log_path |egrep ERROR|egrep from|awk '{print $NF}'|awk -F':' '{print $1}'|sort -n|uniq > $tmp_active_probe_ip

while read line
do
    ip="$line"
    ip_1=$(echo -e "$ip"|awk -F'.' '{print $1}')
    ip_2=$(echo -e "$ip"|awk -F'.' '{print $2}')
    ip_3=$(echo -e "$ip"|awk -F'.' '{print $3}')
    ip_4=$(echo -e "$ip"|awk -F'.' '{print $4}')
    ip_prefix_3=$(echo -e "${ip_1}.${ip_2}.${ip_3}")
    ip_prefix_2=$(echo -e "${ip_1}.${ip_2}")
    ip_prefix_1=$(echo -e "${ip_1}")
    egrep -q "^${ip}" ${all_china_ip_file_path}
    if [ $? -eq 0 ];then
        ip_block=$(egrep "^${ip}" ${all_china_ip_file_path}|egrep -v "^$")
        $block_ip_tool ${ip_block}
        continue
    fi
    egrep -q "^${ip_prefix_3}" ${all_china_ip_file_path}
    if [ $? -eq 0 ];then
        ip_block=$(egrep "^${ip_prefix_3}" ${all_china_ip_file_path}|egrep -v "^$")
        for i in $ip_block
        do
            $block_ip_tool $i
        done
        continue
    fi
    egrep -q "^${ip_prefix_2}" ${all_china_ip_file_path}
    if [ $? -eq 0 ];then
        ip_block=$(egrep "^${ip_prefix_2}" ${all_china_ip_file_path}|egrep -v "^$")
        for i in $ip_block
        do
            $block_ip_tool $i
        done
        continue
    fi
    egrep -q "^${ip_prefix_1}" ${all_china_ip_file_path}
    if [ $? -eq 0 ];then
        ip_block=$(egrep "^${ip_prefix_1}" ${all_china_ip_file_path}|egrep -v "^$")
        for i in $ip_block
        do
            $block_ip_tool $i
        done
        continue
    fi
done < $tmp_active_probe_ip

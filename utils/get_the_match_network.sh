#!/bin/bash

if [ $# -ne 3 ];then
    echo -e "Usage:\n\t$0 log_path [1-3] all_china_ip_file_path"
    exit 1
fi

log_path="$1"
prefix_num=$2
all_china_ip="$3"

if [ ! -f $log_path ];then
    echo -e "Sorry log file not found"
    exit 1
fi
if [ ! -f "get_ip_prefix_str.py" ];then
    echo -e "Sorry. I need get_ip_prefix_str.py at the same path with me"
    exit 1
else
    chmod +x get_ip_prefix_str.py
fi
if [ ! -f $all_china_ip ];then
    echo -e "Sorry all_china_ip file not found"
    exit 1
fi

bad_ips=$(cat $log_path|egrep ERROR|egrep from|awk '{print $NF}'|awk -F':' '{print $1}'|sort -n|uniq)


if [ $prefix_num -eq 1 ];then
    for i in $bad_ips
    do
        t_prefix=$(./get_ip_prefix_str.py $i 1)
        echo $t_prefix >> /tmp/ss_fuck_gfw_prefix_1
    done
    cat /tmp/ss_fuck_gfw_prefix_1|egrep -v "^$"|sort -n|uniq >> /tmp/ss_fuck_gfw_prefix_1_tmp
    touch /tmp/ss_fuck_gfw_prefix_1_result
    while read line
    do
        egrep -q "^$line" $all_china_ip
        if [ $? -eq 0 ];then
            egrep "^$line" $all_china_ip >> /tmp/ss_fuck_gfw_prefix_1_result
        else
            echo -e "$line" >> /tmp/ss_last_not
        fi
    done < /tmp/ss_fuck_gfw_prefix_1_tmp
    echo -e "result as follows:\n"
    cat /tmp/ss_fuck_gfw_prefix_1_result
    mv /tmp/ss_fuck_gfw_prefix_1_result /tmp/ss_last
    mv /tmp/ss_last_not /tmp/ss_last_not_match
    rm /tmp/ss_fuck_gfw_*
    exit 1
fi
if [ $prefix_num -eq 2 ];then
    for i in $bad_ips
    do
        t_prefix=$(./get_ip_prefix_str.py $i 2)
        echo $t_prefix >> /tmp/ss_fuck_gfw_prefix_2
    done
    cat /tmp/ss_fuck_gfw_prefix_2|egrep -v "^$"|sort -n|uniq >> /tmp/ss_fuck_gfw_prefix_2_tmp
    touch /tmp/ss_fuck_gfw_prefix_2_result
    while read line
    do
        egrep -q "^$line" $all_china_ip
        if [ $? -eq 0 ];then
            egrep "^$line" $all_china_ip >> /tmp/ss_fuck_gfw_prefix_2_result
        else
            echo -e "$line" >> /tmp/ss_last_not
        fi
    done < /tmp/ss_fuck_gfw_prefix_2_tmp
    echo -e "result as follows:\n"
    cat /tmp/ss_fuck_gfw_prefix_2_result
    mv /tmp/ss_fuck_gfw_prefix_2_result /tmp/ss_last
    mv /tmp/ss_last_not /tmp/ss_last_not_match
    rm /tmp/ss_fuck_gfw_*
    exit 1
fi
if [ $prefix_num -eq 3 ];then
    for i in $bad_ips
    do
        t_prefix=$(./get_ip_prefix_str.py $i 3)
        echo $t_prefix >> /tmp/ss_fuck_gfw_prefix_3
    done
    cat /tmp/ss_fuck_gfw_prefix_3|egrep -v "^$"|sort -n|uniq >> /tmp/ss_fuck_gfw_prefix_3_tmp
    touch /tmp/ss_fuck_gfw_prefix_3_result
    while read line
    do
        egrep -q "^$line" $all_china_ip
        if [ $? -eq 0 ];then
            egrep "^$line" $all_china_ip >> /tmp/ss_fuck_gfw_prefix_3_result
        else
            echo -e "$line" >> /tmp/ss_last_not
        fi
    done < /tmp/ss_fuck_gfw_prefix_3_tmp
    echo -e "result as follows:\n"
    cat /tmp/ss_fuck_gfw_prefix_3_result
    mv /tmp/ss_fuck_gfw_prefix_3_result /tmp/ss_last
    mv /tmp/ss_last_not /tmp/ss_last_not_match
    rm /tmp/ss_fuck_gfw_*
    exit 1
fi
#!/bin/bash


if [ -f "all_china_ip.txt" -a -f "block_ip.sh" ];then
    chmod +x block_ip.sh
    while read line
    do
        ./block_ip.sh $line
    done < ./all_china_ip.txt
else
    echo -e "Sorry .. Maybe no all_china_ip.txt or block_ip.sh"
    exit 1
fi

    
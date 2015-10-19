#!/bin/bash

if [ $(id -u) -ne 0 ];then
	echo -e "You need to be root to run me.. Holy God I love you.."
	exit 1
fi

if [ $# -ne 1 ];then
    echo -e "Usage:\n\t$0 IP"
    exit 1
fi

IP="$1"

os=$(uname)
if [ "$os" == "Linux" ];then
	mtr_bin="/usr/sbin/mtr"
elif [ "$os" == "Darwin" ];then
	mtr_bin="/usr/local/sbin/mtr"
else
	echo -e "Sorry. No mtr found..EXIT Now"
	exit 1
fi

if [ ! -f $mtr_bin -o ! -x $mtr_bin ];then
	echo -e "Sorry.. mtr bin not found or not executable"
	exit 1
fi

echo -e "------------------------------------"
echo -e "every ping 0.1 second 100 counts"
echo -e "------------------------------------"
$mtr_bin -c 100 -n -w -e -r $IP -i 0.1
echo -e "\n"
echo -e "------------------------------------"
echo -e "every ping 0.5 second 100 counts"
echo -e "------------------------------------"
$mtr_bin -c 100 -n -w -e -r $IP -i 0.5
echo -e "\n"
echo -e "------------------------------------"
echo -e "every ping 0.1 second 100 counts with ip to hostname"
echo -e "------------------------------------"
$mtr_bin -c 100 -w -e -r $IP -i 0.1
echo -e "\n"

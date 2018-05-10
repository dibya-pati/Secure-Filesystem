#! /bin/sh
co=1
while [ $co -lt 100 ]
do
	cat /proc/fs/sgfs/aq-status
	co=`expr $co + 1`
	sleep 1
done

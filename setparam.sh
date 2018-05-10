#! /bin/sh
echo $1 > /proc/sys/fs/sgfs/max_files
cat /proc/sys/fs/sgfs/max_files
echo $2 > /proc/sys/fs/sgfs/queue_len
cat /proc/sys/fs/sgfs/queue_len
echo $3 > /proc/sys/fs/sgfs/bg_freq
cat /proc/sys/fs/sgfs/bg_freq

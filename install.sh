make clean
umount /mnt/sgfs/
rmmod sgfs
make
make utils
insmod /usr/src/hw3-cse506g03/fs/sgfs/sgfs.ko
mount -t sgfs -o key=abcdABCDqwerQWER /usr/src/hw3-cse506g03/hw3/mnt-sgfs/ /mnt/sgfs
dmesg | tail

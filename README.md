--------------
Team Members:
--------------
Dibyajyoti Pati
Alok Thatikunta 
 
--------------
Design:
--------------
1. Maintain a Global Trash bin i.e., one common bin for all users
2. Mount time key is necessary
3. User can add key using ioctl ops. If key is not present for user, then mount key is used
4. Background cleaning: Efficient sorting of list (merge sort)
5. sys params (min, max values)
6. crypto_api: Encryption (skcipher: cbc(aes)), Compression (deflate: works quite good compared to others, tested on limited small files)
7. Single mount system (singleton mount)
8. Cannot create files/dir in .sg (trashbin folder)

----------------------------------------------------------------------------------------------------------------
Setup:
--------------
git clone ssh://athatikunta@scm.cs.stonybrook.edu:130/scm/cse506git-s18/hw3-cse506g03
#### Install all modules
cd /usr/src/hw3-cse506g03/
make
make modules
make modules_install install

#### Install sgfs, c (ioctl codes) modules
cd /usr/src/hw3-cse506g03/fs/sgfs
umount /mnt/sgfs
rmmod sgfs
make
make utils
insmod /usr/src/hw3-cse506g03/fs/sgfs/sgfs.ko
mount -t sgfs -o key=abcdABCDqwerQWER /usr/src/hw3-cse506g03/hw3/mnt-sgfs/ /mnt/sgfs
(or)
./install.sh
----------------------------------------------------------------------------------------------------------------
Evaluation:
----------------------------------------------------------------------------------------------------------------
Functionality:
----------------------------------------------------------------------------------------------------------------
Move unlinked files to trashbin:	[done]
--------------
cmd (view trashbin): 			ls -alh /mnt/sgfs/.sg/
----------------------------------------------------------------------------------------------------------------
Support for 3 flags in clone(2):	[done]
--------------
cmd (plaintext):			./del -m -f=/mnt/sgfs/[filename]
cmd (compression):			./del -mc -f=/mnt/sgfs/[filename]
cmd (encryption):			./del -me -f=/mnt/sgfs/[filename]
cmd (compression, encryption):		./del -mce -f=/mnt/sgfs/[filename]
----------------------------------------------------------------------------------------------------------------
Unlink small files (<=4KB) sync:	[done]
----------------------------------------------------------------------------------------------------------------
Unlink large files async:		[done]
----------------------------------------------------------------------------------------------------------------
Support for /proc params:		[done]
--------------
cmd (update max files in trashbin): 	echo 15 > /proc/sys/fs/sgfs/max_files
cmd (update queue length):		echo 15 > /proc/sys/fs/sgfs/queue_len
cmd (update background freq):		echo 15 > /proc/sys/fs/sgfs/bg_freq
----------------------------------------------------------------------------------------------------------------
ioctl(2) to recover lost file: 		[done]
--------------
cmd (restore file):			./restore -f=/mnt/sgfs/.sg/[filename]
----------------------------------------------------------------------------------------------------------------
Delete older files from trashbin:	[done]
--------------
kthread(): 				bg-cleaning
----------------------------------------------------------------------------------------------------------------
Support to list queue's content:	[done]
--------------
cmd (view proc file):			cat /proc/fs/sgfs/aq-status
cmd (continuous view, updated every 1s):./proc.sh
----------------------------------------------------------------------------------------------------------------
ioctl to set cipher:			[done]
cmd 					 ./updatekey -f=/mnt/sgfs/.keyring -k=7777jjjjuuuuyyyy
----------------------------------------------------------------------------------------------------------------
Support to purge trashbin completely:	[done]	./purge -f=<path of sgfs .sg folder>
						./purge -f=/mnt/sgfs/.sg
----------------------------------------------------------------------------------------------------------------
Test programs:				[ done] 
cmd					make tests
----------------------------------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------------------------------
Demo:
--------------
Code Inspection:			[done]
cmd (run checkpatch.pl):		./checkpatch.pl --no-tree -f /usr/src/hw3-cse506g03/fs/sgfs/*.c > /usr/src/hw3-cse506g03/fs/sgfs/Data/checkpatch.txt
cmd (change dir):			cd /usr/src/hw3-cse506g03/fs/sgfs/Data
cmd (shows errors):			grep --include=checkpatch.txt "errors" -Rhn
----------------------------------------------------------------------------------------------------------------
Extra Credit:
--------------
Async cancel job:			./canceljob -f=/mnt/sgfs/.metadata -j=[jobid]
					jobid to be retrieved from proc
----------------------------------------------------------------------------------------------------------------

--------------
Documentation and Submissions:		[done] 
Written above

----------------------------------------------------------------------------------------------------------------
References:
--------------
Linux Kernel: https://elixir.bootlin.com/linux/v4.6/source
Checkpatch perl script: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl
Clone: http://man7.org/linux/man-pages/man2/clone.2.html
Link-list: https://davejingtian.org/2013/04/03/linux-kernel-linked-list/
http://tuxthink.blogspot.com

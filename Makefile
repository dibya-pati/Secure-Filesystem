SGFS_VERSION="0.1"

EXTRA_CFLAGS += -DSGFS_VERSION=\"$(SGFS_VERSION)\"
INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

obj-$(CONFIG_SG_FS) += sgfs.o 
sgfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all:
	make  -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
utils:
	gcc -o del del.c
	gcc -o purge purge.c
	gcc -o restore restore.c
	gcc -o updatekey updatekey.c
	gcc -o canceljob canceljob.c
tests:
	sh ./smalltest.sh
	sh ./mediumtest.sh
	sh ./purge.sh
	sh ./setparam.sh 20 20 20
	sh ./largetest.sh
	sh ./purge.sh
	sh ./setparam.sh 5 5 5
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f del purge restore updatekey canceljob
	

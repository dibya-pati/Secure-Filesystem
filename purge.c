#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define SGCTL_PURGE _IO('d', 4)

static void print_usage(void) 
{
	printf("Incorrect params\n");
	printf("./purge -f=/path-to-mnt/.sg\n");
}

int main(int argc, char *argv[])
{
	char ch;
	char f_name[4096];
	int err = 0, fd = 0;
	if (argc < 2) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch(ch) {
		case 'f':
			strcpy(f_name, optarg+1);
			if (strcmp(f_name+strlen(f_name)-3, ".sg")) {
				print_usage();
				exit(EXIT_FAILURE);
			}
			break;
		default:
			print_usage();
			exit(EXIT_FAILURE);
		}
	}

	fd = open(f_name, O_RDONLY);

	if (fd < 0) {
		puts("File open fail");
		exit(EXIT_FAILURE);
	}
	err = ioctl(fd, SGCTL_PURGE);
	err = errno;
	if (0 == err) {
		puts("Success purge");
	}
	else {
		printf("Fail: Purge returned [%d]\n", err);
	}
	close(fd);
	exit(EXIT_SUCCESS);
}


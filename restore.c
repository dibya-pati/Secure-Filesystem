#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <error.h>
#include "sgfscommon.h"

#define SGCTL_RECOVER _IO('b', 2)

int main(int argc, char **argv)
{
	int fd;
	int err = 0;
	char ch;
	char filename[4096];
	int32_t value, number = 25;

	/* need persistent file here, preferably SHA file for filename*/
	if (argc < 2)
		return -1;

	while ((ch = getopt(argc, argv, "f:")) != -1)
		switch (ch) {
		case 'f':
			//printf("%s\n",optarg);
			/*take filename here for SHA1 hash file*/
			strcpy(filename, optarg+1);
			// printf("%s\n",filename);
			break;

		default:
			return -1;
		}


	printf("%s\n", filename);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		printf("%d\n", fd);
		return 0;
	}

	err = ioctl(fd, SGCTL_RECOVER);
	/*investigate the err from syscall kern*/
	// if (-1 == err)
	//	printf("Wrong key entered\n");
	// else if (0 == err)
	//	printf("Key exists, fs updated\n");
	// else if (1 == err)
	//	printf("key inserted and persistent store udpated\n");

	close(fd);
}

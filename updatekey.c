#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <error.h>
#include "sgfscommon.h"

#define SGCTL_UPDATEKEY _IOW('a', 1, int32_t*)

int main(int argc, char **argv)
{
	int fd;
		int err = 0;
		char ch;
		char filename[100];
		char keystr[MAX_KEYLEN];
	int32_t value, number = 25;

		/* need persistent file here, preferably SHA file for filename*/
		if (argc < 2)
			return -1;

		while ((ch = getopt(argc, argv, "f:k:")) != -1)
			switch (ch) {
			case 'k':
					//printf("%s\n",optarg);
					/*take filename here for SHA1 hash file*/
				if (strlen(optarg) > (MAX_KEYLEN-1)+4)
						//strcpy(filename,optarg);
					return -1;
				strcpy(keystr, optarg+1);
				printf("%s", keystr);
				break;
			case 'f':
					//printf("%s\n",optarg);
					/*take filename here for SHA1 hash file*/
				strcpy(filename, optarg+1);
				printf("\n%s", filename);
				break;
			default:
				return -1;
			}


		printf("[%s]\n", filename);
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			printf("%d\n", fd);
			return 0;
		}

	printf("Writing key to fs\n");
		printf(keystr);
	err = ioctl(fd, SGCTL_UPDATEKEY, (char *) keystr);
		/*investigate the err from syscall kern*/
	err = errno;
		if (err)
			printf("Failed to enter key err=[%d]\n",err);
		else if (err == 0)
			printf("Key exists, fs updated\n");

	close(fd);
}

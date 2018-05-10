#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <error.h>
#include <errno.h>
#include "sgfscommon.h"

#define SGCTL_CANCEL _IOW('e', 5, int32_t*)

int main(int argc, char **argv)
{
	int fd;
	int err = 0;
	char ch;
	char filename[100];
	int jobid;
	char jobidstr[MAX_JOBNUM+1];
	int32_t value, number = 25;

	/* need persistent file here, preferably SHA file for filename*/
	if (argc < 2)
		return -1;

	while ((ch = getopt(argc, argv, "j:f:")) != -1)
		switch (ch) {
		case 'j':
		//printf("%s\n",optarg);
		/*take filename here for SHA1 hash file*/
			if (strlen(optarg) > MAX_JOBNUM+1){
				printf("Invalid job number/length\n");
				return -1;
			}
			strcpy(jobidstr, optarg+1);
			jobid = strtol(jobidstr, NULL,10);
			if (errno == ERANGE){
				printf("Invalid Job ID:[%s]",jobidstr);
				return errno;
			}
			break;
		case 'f':
			strcpy(filename, optarg+1);
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

	printf("Canceling job\n");
	printf("Job ID:[%d]",jobid);
	err = ioctl(fd, SGCTL_CANCEL, jobid);
	/*investigate the err from syscall kern*/
	if (EINVAL == errno)
		printf("Job not found in queue Or Completed Execution\n ");
	else if (errno == 0)
		printf("Job found and removed from queue\n");

	close(fd);
}

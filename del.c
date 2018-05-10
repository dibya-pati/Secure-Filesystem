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
#define _GNU_SOURCE

#define CLONE_PROT              0x00001000
#define CLONE_DETACHED          0x00400000

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */
#define SGCTL_RM _IO('c', 3)


int err = 0;
static void print_usage(void)
{
	printf("Incorrect params\n");
	printf("Move:	./del -m   -f=/path-to-mnt/<file-name>\n");
	printf("Zip:	./del -mc  -f=/path-to-mnt/<file-name>\n");
	printf("Enc:	./del -me  -f=/path-to-mnt/<file-name>\n");
	printf("Cmp&Enc:./del -mce -f=/path-to-mnt/<file-name>\n");
}

static int cf(void *fileName)
{
	int fd = open((char *)fileName, O_RDONLY);


	if (fd < 0) {
		err = -EINVAL;
		return err;
	}
	err = ioctl(fd, SGCTL_RM);
	err = errno;
	if (err)
		printf("queue addition failed with error with error[%d]",err);
	close(fd);
	return err;
}

static void cf2(char *f_name)
{
	int fd = open(f_name, O_RDONLY);
	if (fd < 0) {
		puts("Fail: File open");
		return;
	}
	ioctl(fd, SGCTL_RM);
	err = errno;
	close(fd);
}


int main(int argc, char *argv[])
{
	char *stack;                    /* Start of stack buffer */
	char *stackTop;                 /* End of stack buffer */
	pid_t pid;
	char ch;

	if (argc < 2) {
		print_usage();
		exit(EXIT_FAILURE);
	}
	int flag_mv = 0, flag_zip = 0, flag_enc = 0;
	char f_name[4096];

	while ((ch = getopt(argc, argv, "cemf:")) != -1) {
		switch (ch) {
		case 'c':
			flag_zip = 1;
			break;
		case 'e':
			flag_enc = 1;
			break;
		case 'm':
			flag_mv = 1;
			break;
		case 'f':
			strcpy(f_name, optarg+1);
			break;
		default:
			print_usage();
			exit(EXIT_FAILURE);
		}
	}

	//printf("Flags: mv-%d zip-%d enc-%d\n", flag_mv, flag_zip, flag_enc);
	//printf("Filename: %s\n", f_name);

	/* Allocate stack for child */

	stack = malloc(STACK_SIZE);
	if (stack == NULL)
		errExit("malloc");
	stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */

	int clone_flags = 0;

	if (flag_enc) {
		if (!flag_mv) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		clone_flags |= CLONE_PROT;
	}
	if (flag_zip) {
		if (!flag_mv) {
			print_usage();
			exit(EXIT_FAILURE);
		}
		clone_flags |= CLONE_DETACHED;
	}

	if (flag_mv) {
		if (!flag_zip && !flag_enc) {
			cf2(f_name);
			printf("del returned [%d]\n", err);
			exit(EXIT_SUCCESS);
		}
	}

	char *arg_list[] = {"/bin/rm", "-f", f_name, NULL};

	if (clone_flags == 0) {
		execv("/bin/rm", arg_list);
		printf("Dangerous: exec failed\n");
	}

	pid = clone(cf, stackTop, clone_flags | SIGCHLD, f_name);
	if (pid == -1)
		errExit("clone");
	printf("clone() pid = [%ld]\n", (long) pid);

	/* Parent falls through to here */

	//sleep(1);           /* Give child time to change its hostname */

	if (waitpid(pid, NULL, 0) == -1)    /* Wait for child */
		errExit("waitpid");
	exit(EXIT_SUCCESS);
}


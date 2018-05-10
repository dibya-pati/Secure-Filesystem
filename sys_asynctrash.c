#include "asynctrash.h"
#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <asm/string_64.h>
#include <linux/buffer_head.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/time.h>

asmlinkage extern long (*sysptr)(void *arg);

asmlinkage long asynctrash(void *arg)
{
	iargs *inp_args = NULL;
	int ret = 0;

	inp_args = kmalloc(sizeof(iargs), GFP_KERNEL);
	if (!inp_args) {
		ret =  -ENOMEM;
		goto out;
	}

	ret = copy_from_user((void *) inp_args, arg, sizeof(iargs));
	DEBUGMSG(inp_args->filename);
	DEBUGINT(inp_args->flag_compress);
	DEBUGINT(inp_args->flag_encrypt);
out:
	return ret;
}
static int __init init_sys_asynctrash(void)
{
	printk("installed new sys_asynctrash module\n");
	if (sysptr == NULL)
		sysptr = asynctrash;
	return 0;
}
static void  __exit exit_sys_asynctrash(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_asynctrash module\n");
}
module_init(init_sys_asynctrash);
module_exit(exit_sys_asynctrash);
MODULE_LICENSE("GPL");


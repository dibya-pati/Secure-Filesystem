#include <linux/limits.h>
#include <linux/types.h>

#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
#define DEBUGINT(value) printk("KERN_INFO [%d]%s: %s : [%d]\n", __LINE__, __FILE__, __func__, value)
#define DEBUGINT2(str, value) printk("KERN_INFO [%d]%s: %s : [%s %d]\n", __LINE__, __FILE__, __func__, str, value)
#define DEBUGMSG(msg) printk("KERN_INFO [%d]%s: %s : [%s]\n", __LINE__, __FILE__, __func__, msg)
#define DEBUGMSG2(str, msg) printk("KERN_INFO [%d]%s: %s : [%s %s]\n", __LINE__, __FILE__, __func__, str, msg)

typedef struct iargs {
	char filename[PATH_MAX];
	u_int flag_compress;
	u_int flag_encrypt;
}iargs;


/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _SGFS_H_
#define _SGFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include <linux/seq_file.h>
#include <linux/spinlock_types.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include "sgfscommon.h"

/* the file system name */
#define SGFS_NAME "sgfs"

/* sgfs root inode number */
#define SGFS_ROOT_INO     1

#define TIMESTRLEN 20
#define UIDSTRLEN 5
#define TIMEBUF_LEN 19

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
#define DEBUGINT(value) printk("KERN_INFO [%d]%s: %s : [%d]\n", __LINE__, __FILE__, __func__, value)
#define DEBUGINT2(str, value) printk("KERN_INFO [%d]%s: %s : [%s %d]\n", __LINE__, __FILE__, __func__, str, value)
#define DEBUGMSG(msg) printk("KERN_INFO [%d]%s: %s : [%s]\n", __LINE__, __FILE__, __func__, msg)
#define DEBUGMSG2(str, msg) printk("KERN_INFO [%d]%s: %s : [%s %s]\n", __LINE__, __FILE__, __func__, str, msg)
#define DENTRY_UID(dentry)((dentry)->d_inode->i_uid.val)

#define SGFS_SB_EDATA(sb_private, idx) ((sb_private)->sgfs_keyring[idx])

#define SGFS_SB_CP_EDATA(dst) ({\
		strcpy(dst.keystr, keystr);\
		memcpy((void *)&dst.uid, (void *)&uid, sizeof(kuid_t));\
		})

/* operations vectors defined in specific files */
extern const struct file_operations sgfs_main_fops;
extern const struct file_operations sgfs_dir_fops;
extern const struct inode_operations sgfs_main_iops;
extern const struct inode_operations sgfs_dir_iops;
extern const struct inode_operations sgfs_symlink_iops;
extern const struct super_operations sgfs_sops;
extern const struct dentry_operations sgfs_dops;
extern const struct address_space_operations sgfs_aops, sgfs_dummy_aops;
extern const struct vm_operations_struct sgfs_vm_ops;
extern const struct export_operations sgfs_export_ops;

extern int sgfs_init_inode_cache(void);
extern void sgfs_destroy_inode_cache(void);
extern int sgfs_init_dentry_cache(void);
extern void sgfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sgfs_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags);
extern struct inode *sgfs_iget(struct super_block *sb,
		struct inode *lower_inode);
extern int sgfs_interpose(struct dentry *dentry, struct super_block *sb,
		struct path *lower_path);
extern struct work_data *ls_data;
/* External file ops */
struct file *file_open(const char *file_path, int flags, int mode);
void file_close(struct file *filp);
int file_read(struct file *filep, char *buf, int len, loff_t offset);
int file_write(struct file *filep, char *buf, int len, loff_t offset);
int file_size(struct file *f);
void work_handler(struct work_struct *work);
extern int chnk_sz;

extern atomic_t q_len;
extern atomic_t job_counter;
extern char *root_pathname;
/* Helper functions */
int sgfs_unlink_default(struct inode *dir, struct dentry *dentry);

extern int get_rootpath(struct dentry *dentry, char **abs_path);
extern int get_abspath(struct dentry *dentry, char **abs_path);
extern int rw_keyring(struct super_block *sb, char *rw_key, int create_flag);

int copy_file_plaintext(struct file *inp, struct file *out);
int decrypt_file(struct file *inp, struct file *out, char *key);
int decrypt_decompress_file(struct file *inp, struct file *out, char *key);
int get_sha1sum(char *buf, int len, char **hash);
int unlink_process(struct dentry *dentry, int flag_encrypt, int flag_compress);
int getKey(char **retkeystr, struct super_block *sb);
void aq_status(struct seq_file *m);

/* Sysctl */
typedef struct sgfs_sysctl_val {
	int min;
	int val;
	int max;
}sgfs_sysctl_val_t;

typedef struct sgfs_params {
	sgfs_sysctl_val_t max_files;
	sgfs_sysctl_val_t queue_len;
	sgfs_sysctl_val_t bg_freq;
}sgfs_params_t;

extern sgfs_params_t sgfs_params;

/* Background thread cleaning */
extern struct task_struct *thread_ls;
extern int iterate(int who);

/* Crypto sha1sum functions */
struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

/* Encryption */
struct crypto_wait {
	struct completion completion;
	int err;
};

struct skcipher_def {
    struct scatterlist sg, sg2;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

/* file private data */
struct sgfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* sgfs inode data in memory */
struct sgfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* sgfs dentry data in memory */
struct sgfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

typedef struct user_key_struct {
	char keystr[MAX_KEYLEN];
	kuid_t uid;
} user_key_struct;

/*
   typedef struct sgfs_encrypt_struct{
   user_key_struct userkeyring[MAX_USERS];
   }sgfs_encrypt_struct;
   */

/* sgfs super-block data in memory */
struct sgfs_sb_info {
	struct super_block *lower_sb;
	int num_users;
	user_key_struct sgfs_keyring[MAX_USERS];
};

extern spinlock_t qlock;
struct work_data {
	struct delayed_work work;
	struct list_head node;
	struct dentry *dentry;
	int job_id;
	atomic_t cancel_job;	
	int flag_compress;
	int flag_encrypt;
	struct timespec ts;
};

extern struct workqueue_struct *wq;
/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sgfs_inode_info structure, SGFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sgfs_inode_info *SGFS_I(const struct inode *inode)
{
	return container_of(inode, struct sgfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SGFS_D(dent) ((struct sgfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SGFS_SB(super) ((struct sgfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SGFS_F(file) ((struct sgfs_file_info *)((file)->private_data))

/*get super block private data*/
static inline struct sgfs_sb_info *
sgfs_superblock_to_private(struct super_block *sb)
{
	return (struct sgfs_sb_info *)sb->s_fs_info;
}

static inline uid_t get_uid_val(void)
{

	return current_cred()->uid.val;

}
static const inline kuid_t *getuid_p(void)
{

	return &(current_cred()->uid);

}

/* file to lower file */
static inline struct file *sgfs_lower_file(const struct file *f)
{
	return SGFS_F(f)->lower_file;
}

static inline void sgfs_set_lower_file(struct file *f, struct file *val)
{
	SGFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sgfs_lower_inode(const struct inode *i)
{
	return SGFS_I(i)->lower_inode;
}

static inline void sgfs_set_lower_inode(struct inode *i, struct inode *val)
{
	SGFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *sgfs_lower_super(
		const struct super_block *sb)
{
	return SGFS_SB(sb)->lower_sb;
}

static inline void sgfs_set_lower_super(struct super_block *sb,
		struct super_block *val)
{
	SGFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void sgfs_get_lower_path(const struct dentry *dent,
		struct path *lower_path)
{
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(lower_path, &SGFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_put_lower_path(const struct dentry *dent,
		struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void sgfs_set_lower_path(const struct dentry *dent,
		struct path *lower_path)
{
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(&SGFS_D(dent)->lower_path, lower_path);
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&SGFS_D(dent)->lock);
	SGFS_D(dent)->lower_path.dentry = NULL;
	SGFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;

	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(&lower_path, &SGFS_D(dent)->lower_path);
	SGFS_D(dent)->lower_path.dentry = NULL;
	SGFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SGFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

#endif	/* not _SGFS_H_ */

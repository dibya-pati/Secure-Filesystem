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

#include "sgfs.h"
#include <linux/module.h>

char keystr[MAX_KEYLEN];
kuid_t uid;
struct workqueue_struct *wq;
atomic_t q_len;
struct task_struct *thread_ls;
char *root_pathname;
struct work_data *ls_data;
spinlock_t qlock;
static char *message;
static int read_p;
atomic_t is_mounted;
static struct proc_dir_entry *proc_sgfs;
static struct ctl_table_header *sys_sgfs;
atomic_t job_counter;
/*call the relevant unlinking process as per the flags
 *call process unlink then sgfs_unlink to remove the file
 */
void work_handler(struct work_struct *work)
{
	//struct work_data * data = (struct work_data *)work;
	struct work_data *data = NULL;
	struct dentry *dentry = NULL;
	int err = 0;

	data = container_of((struct delayed_work *)work, struct work_data, work);

	if (data->dentry) {
		dentry = data->dentry;
		/* test code*/
		if (atomic_read(&data->cancel_job))
			goto out;
		if (!(!strcmp(dentry->d_parent->d_iname, ".sg") &&\
				!strcmp(dentry->d_parent->d_parent->d_iname, "/"))) {
			err = unlink_process(dentry, data->flag_encrypt, data->flag_compress);
			if (err) {
				DEBUGMSG("unlink process failed");
				goto out;
			}
		}
		/*second call to remove the file*/
		err = vfs_unlink(d_inode(dentry->d_parent), dentry, NULL);
out:
		spin_lock(&qlock);
		list_del(&data->node);
		atomic_dec(&q_len);
		if (data)
			kfree(data);
		spin_unlock(&qlock);
	} else{
		DEBUGMSG("Dummy node clearing");
	}

}
void aq_status(struct seq_file *m)
{

	struct list_head *itr = NULL;
	struct work_data *wd = NULL;
	struct tm tm;

	spin_lock(&qlock);

	//DEBUGMSG("GO_out");
	list_for_each(itr, &ls_data->node) {
		wd = list_entry(itr, struct work_data, node);
		if (wd) {
			if (wd->dentry) {
				time_to_tm(wd->ts.tv_sec, 0, &tm);
				seq_printf(m, "File-name:\t%s\nFile-size:\t%lld kb\n\
					Deleted time:\t%04ld-%02d-%02d-%02d:%02d:%02d\n\
					Job ID:\t%04d\nCompress:\t%d\nEncrypt:\t%d", \
					wd->dentry->d_name.name, \
					(wd->dentry->d_inode->i_size)/1000, \
					tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,\
					tm.tm_hour, tm.tm_min, tm.tm_sec, wd->job_id,\
					 wd->flag_compress, wd->flag_encrypt);
				//DEBUGMSG(wd->dentry->d_name.name);
			} else {
				DEBUGMSG("Dangerous: wd dentry fail");
			}
		} else {
			DEBUGMSG("Dangerous: wd fail");
		}
	}
	spin_unlock(&qlock);
}

static int thread_ls_fn(void *arg)
{
	char *mnt_path = kmalloc(PATH_MAX, GFP_KERNEL);
	int err = 0;

	strcpy(mnt_path, (char *)arg);
	while (1) {
		if (kthread_should_stop())
			break;
		//DEBUGMSG("kthread run");
		//file = file_open(mnt_path, O_RDONLY, 0777);
		err = iterate(0);
		if (err) {
			goto out;
		}
		ssleep(sgfs_params.bg_freq.val);
	}
out:
	if (mnt_path)
		kfree(mnt_path);
	DEBUGMSG("kthread stopping");
	do_exit(0);
	return err;
}

/*insert_key module
 *inserts master, SU key at idx 0 for the filesystem
 *inputs:sb: superblock pointer
 *return:err
*/

static void insert_key(struct super_block *sb)
{
	/*update the keyring info for the superuser who set the mount*/
	/*update the keyring count by one for the superuser key or default key */
	SGFS_SB(sb)->num_users += 1;
	SGFS_SB_CP_EDATA(SGFS_SB_EDATA(SGFS_SB(sb), 0));
	DEBUGINT2("SB Users: ", SGFS_SB(sb)->num_users);
}

/*create_metafile module
 *creates a meta data file with the original and deleted filanames
 *<size_original_file>,<size_deleted_file><filepath+filename>,\
 *<compress_flag,enc_flag>_<time_string>_<keyid>_<uid>_<filename>
 *in the format
 *inputs:sb: superblock pointer
 *return:err
 */
static int create_metafile(struct super_block *sb)
{

	int err = 0;
	char *meta_filename = ".metadata";
	char *file_name_meta = NULL;
	struct file *meta_file_p = NULL;

	file_name_meta = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!file_name_meta) {
		err = -ENOMEM;
		goto out;
	}

	//err = get_rootpath(sb->s_root, &root_path);
	snprintf(file_name_meta, PATH_MAX, "%s/%s", root_pathname, meta_filename);

	meta_file_p = file_open(file_name_meta, O_APPEND|O_WRONLY, 0666);
	if (meta_file_p && !IS_ERR(meta_file_p)) {
		DEBUGMSG("Success: meta-file exists");
	} else {
		meta_file_p = file_open(file_name_meta, O_CREAT|O_WRONLY, 0666);
		if (!meta_file_p || IS_ERR(meta_file_p)) {
			DEBUGMSG("Fail: meta-file creation failed");
			err = PTR_ERR(meta_file_p);
			goto out;
		}
	}
	/*
	   getnstimeofday(&ts);
	   time_to_tm(ts.tv_sec, 0, &tm);
	   snprintf(timebuf,TIMEBUF_LEN,"\n%04ld-%02d-%02d-%02d:%02d\n",\
	   tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,\
	   tm.tm_hour, tm.tm_min);

	//DEBUGINT( meta_file_p->f_pos);
	file_write(meta_file_p, timebuf, TIMEBUF_LEN, meta_file_p->f_pos);
	*/
	DEBUGMSG("Success: meta-file created/existed");


out:
	if (file_name_meta)
		kfree(file_name_meta);
	if (meta_file_p)
		file_close(meta_file_p);
	return err;
}
/*
 * Input: .keyring file pointer
 * Output: 1 (user not present: Insert key)
 * Output: 0 (user exists: Correct key)
 * Output: -EINVAL (user exists: Wrong key)
 */
int rw_keyring(struct super_block *sb, char *rw_key, int create_flag)
{
	int err = 0, flag = 1;
	int chnk_keyring_sz = 40;
	loff_t offset = 0, file_sz = 0, bytes = 0;
	char *str_id = NULL, *hash_id = NULL, *hash_key = NULL, *buf_id = NULL, *buf_key = NULL;

	char *hash_name = ".keyring";
	char *file_name_sg;
	struct file *file_key = NULL;

	uid_t rw_id = current_cred()->uid.val;

	DEBUGINT(rw_id);

	file_name_sg = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!file_name_sg) {
		err = -ENOMEM;
		goto out_rw;
	}
	//err = get_rootpath(sb->s_root, &file_path_sg);
	//if (err)goto out_rw;
	snprintf(file_name_sg, PATH_MAX, "%s/%s", root_pathname, hash_name);

	file_key = file_open(file_name_sg, O_RDWR, 0666);
	if (file_key && !IS_ERR(file_key)) {
		if (create_flag == 1)
			DEBUGMSG("Success: Keyring - File Exists");
	} else {
		if (create_flag == 1) {
			DEBUGMSG(file_name_sg);
			file_key = file_open(file_name_sg, O_CREAT|O_RDWR, 0666);
			if (!file_key || IS_ERR(file_key)) {
				DEBUGMSG("Fail: Keyring - Couldn't create file");
				goto out_rw;
			}
			DEBUGMSG("Success: Keyring - Created file");
		} else {
			err = -EINVAL;
			goto out_rw;
		}
	}

	file_sz = file_size(file_key);
	str_id = kmalloc(40, GFP_KERNEL); // Max str length of key
	if (!str_id) {
		err = -ENOMEM;
		goto out_rw;
	}
	hash_id = kmalloc(40, GFP_KERNEL);
	if (!hash_id) {
		err = -ENOMEM;
		goto out_rw;
	}
	hash_key = kmalloc(40, GFP_KERNEL);
	if (!hash_key) {
		err = -ENOMEM;
		goto out_rw;
	}
	buf_id = kmalloc(40, GFP_KERNEL);
	if (!buf_id) {
		err = -ENOMEM;
		goto out_rw;
	}
	buf_key = kmalloc(40, GFP_KERNEL);
	if (!buf_key) {
		err = -ENOMEM;
		goto out_rw;
	}

	snprintf(str_id, 40, "%d", rw_id);
	err = get_sha1sum(str_id, (int)strlen(str_id), &hash_id);
	if (err < 0) {
		DEBUGMSG("Dangerous: Keyring - sha1sum");
		goto out_rw;
	}
	err = get_sha1sum(rw_key, (int)strlen(rw_key), &hash_key);
	if (err < 0) {
		DEBUGMSG("Dangerous: Keyring - sha1sum");
		goto out_rw;
	}

	for (offset = 0; offset < file_sz; ) {
		bytes = file_read(file_key, buf_id, chnk_keyring_sz, offset);
		offset += chnk_keyring_sz;
		buf_id[bytes] = '\0';
		bytes = file_read(file_key, buf_key, chnk_keyring_sz, offset);
		offset += chnk_keyring_sz;
		buf_key[bytes] = '\0';
		if (strcmp(buf_id, hash_id) == 0) {
			flag = 0;
			if (strcmp(buf_key, hash_key) == 0) {
				err = 0;
			} else {
				err = -EINVAL;
			}
			goto out_rw;
		}
	}
	if (flag == 1) {
		file_write(file_key, hash_id, chnk_keyring_sz, offset);
		offset += chnk_keyring_sz;
		file_write(file_key, hash_key, chnk_keyring_sz, offset);
		offset += chnk_keyring_sz;
		err = 1;
	}
out_rw:
	if (file_key && !IS_ERR(file_key))
		file_close(file_key);
	if (file_name_sg)
		kfree(file_name_sg);
	if (str_id)
		kfree(str_id);
	if (hash_id)
		kfree(hash_id);
	if (hash_key)
		kfree(hash_key);
	if (buf_id)
		kfree(buf_id);
	if (buf_key)
		kfree(buf_key);
	return err;
}

/*create_sg module
 *creates a .sg folder in the root of the filesystem
 *creates .keyring file with the SHA hash of the user and keys
 *input: sb of the sgfs fs
 *output: error
 */
static int create_sg(struct super_block *sb)
{
	int err = 0;
	char *mnt_name = ".sg";
	struct dentry *par_dentry, *mnt_dentry;

	par_dentry = dget(sb->s_root);
	inode_lock(d_inode(par_dentry));
	mnt_dentry = lookup_one_len(mnt_name, par_dentry, strlen(mnt_name));

	if (IS_ERR(mnt_dentry)) {
		printk("dentry error");
		dput(par_dentry);
		goto out_mnt_unlock;
	}

	if (d_really_is_positive(mnt_dentry)) {
		DEBUGMSG("Success: .sg - Folder exists");
		goto create_keyring;
	}

	err = vfs_mkdir(d_inode(par_dentry), mnt_dentry, 777);
	DEBUGMSG("Success: .sg - Created folder");

create_keyring:
	err = rw_keyring(sb, keystr, 1);	//create_flag: 1 (so can create file)
	if (err == 1) {
		DEBUGMSG("Success: Keyring - Updated");
	} else if (err == 0) {
		DEBUGMSG("Success: Keyring - No update");
	} else {
		DEBUGMSG("Fail: Keyring - Wrong key");
	}

	err = create_metafile(sb);

	dput(par_dentry);
	dput(mnt_dentry);
out_mnt_unlock:
	inode_unlock(d_inode(par_dentry));
	// DEBUGINT(err);
	return err;
}

/*
 * There is no need to lock the sgfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sgfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0, err_sg;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	char *arg_path = NULL;

	arg_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!arg_path) {
		err = -ENOMEM;
		goto out;
	}

	if (!dev_name) {
		printk(KERN_ERR
				"sgfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sgfs: error accessing lower directory '%s'\n",
				dev_name);
		goto out;
	}
	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sgfs_sb_info), GFP_KERNEL);
	if (!SGFS_SB(sb)) {
		printk(KERN_CRIT "sgfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sgfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sgfs_sops;

	sb->s_export_op = &sgfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = sgfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sgfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sgfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
				"sgfs: mounted on top of %s type %s\n",
				dev_name, lower_sb->s_type->name);

	err_sg = create_sg(sb);
	//DEBUGINT(err_sg);
	if (err_sg < 0) {
		err = -EINVAL;
		goto out;
	}

	insert_key(sb);

	/* Do-not do error handling, mnt_path keeps getting changed */
	//err = get_rootpath(sb->s_root, &mnt_path);
	snprintf(arg_path, PATH_MAX, "%s/.sg", root_pathname);

	/* Create kthread for background cleaning */

	thread_ls = kthread_run(thread_ls_fn, (void *)arg_path, "bg-cleaning");
	if (thread_ls)
		DEBUGMSG("kthread created");
	else
		DEBUGMSG("kthread already exists");


	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SGFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	/* Do-not do error handling, kfree causes thread_fn_ls arg to loose args */
	//if (arg_path) kfree(arg_path);
	return err;
}

struct dentry *sgfs_mount(struct file_system_type *fs_type, int flags,
		const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	const struct cred *cred = current_cred();
	if(!atomic_inc_and_test(&is_mounted)){
		atomic_dec(&is_mounted);
		return ERR_PTR(-EBUSY);
	}
	
	if (raw_data == NULL) {
		DEBUGMSG("No key given");
		// memcpy(key_default, NO_KEY, 16);
	}
	/*check for keyword "key=" and key of length 16*/
	else if ((strlen(raw_data) == (MAX_KEYLEN-1)+4) &&\
			!strncmp(raw_data, "key=", 4)) {
		DEBUGMSG("Key Entered Successfully!");
		// memcpy(key_default, raw_data+4, 16);
	} else {
		printk("Raw data: %d\n", (int)(strlen(raw_data)));
		DEBUGMSG("Key length should be 16");
		return ERR_PTR(-EINVAL);
	}
	/*test code*/
	root_pathname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!root_pathname) {
		return ERR_PTR(-ENOMEM);
	}


	strcpy(root_pathname, dev_name);
	DEBUGMSG(dev_name);
	//return ERR_PTR(-EINVAL);
	/*test code ends*/
	strcpy(keystr, raw_data+4);
	uid = cred->uid;

	return mount_nodev(fs_type, flags, lower_path_name,
			sgfs_read_super);
}

/**
 * sgfs_kill_block_super
 * @sb: The sgfs super block
 *
 * Used to bring the superblock down and free the private data.
 */
static void sgfs_kill_block_super(struct super_block *sb)
{
	if (thread_ls) {
		kthread_stop(thread_ls);
		DEBUGMSG("kthread stop");
	}
	atomic_dec(&is_mounted);
	generic_shutdown_super(sb);
}

static int aq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Queue length:\t\t%d\n", atomic_read(&q_len));
	aq_status(m);
	return 0;
}

static int aq_open(struct inode *inode, struct file *file)
{
	return single_open(file, aq_show, NULL);
}

static const struct file_operations aq_fops = {
	.owner		= THIS_MODULE,
	.open		= aq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

sgfs_params_t sgfs_params = {
	.max_files	= {	0, 	15,	100},
	.queue_len	= {	0,	10,	100},
	.bg_freq	= {	1,	5,	100}
};

static struct ctl_table sgfs_table[] = {
	{
		.procname	= "max_files",
		.data		= &sgfs_params.max_files.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sgfs_params.max_files.min,
		.extra2		= &sgfs_params.max_files.max
	},
	{
		.procname	= "queue_len",
		.data		= &sgfs_params.queue_len.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sgfs_params.queue_len.min,
		.extra2		= &sgfs_params.queue_len.max
	},
	{
		.procname	= "bg_freq",
		.data		= &sgfs_params.bg_freq.val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sgfs_params.bg_freq.min,
		.extra2		= &sgfs_params.bg_freq.max
	},
	{}
};
static struct ctl_table sgfs_dir_table[] = {
	{
		.procname	= "sgfs",
		.mode		= 0555,
		.child		= sgfs_table
	},
	{}
};

static struct ctl_table sgfs_root_table[] = {
	{
		.procname	= "fs",
		.mode		= 0555,
		.child		= sgfs_dir_table
	},
	{}
};

static struct file_system_type sgfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SGFS_NAME,
	.mount		= sgfs_mount,
	//.kill_sb	= generic_shutdown_super,
	.kill_sb	= sgfs_kill_block_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SGFS_NAME);

static int __init init_sgfs_fs(void)
{
	int err = 0;
	atomic_set(&is_mounted, -1);
	pr_info("Registering sgfs " SGFS_VERSION "\n");

	err = sgfs_init_inode_cache();
	if (err)
		goto out;
	err = sgfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sgfs_fs_type);

	/* Proc creation */
	proc_sgfs = NULL;
	proc_sgfs = proc_mkdir("fs/sgfs", NULL);
	proc_create("aq-status", S_IRUGO, proc_sgfs, &aq_fops);
	read_p = 1;
	message = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!message) {
		DEBUGMSG("Dangerous: malloc");
		err = -ENOMEM;
	}
	DEBUGMSG("Success: /proc/fs/sgfs/aq-status proc created");

	sys_sgfs = NULL;
	sys_sgfs = register_sysctl_table(sgfs_root_table);
	if (!sys_sgfs) {
		DEBUGMSG("Dangerous: sys call");
		err = -ENOMEM;
	}
	DEBUGMSG("Success: /proc/sys/fs/sgfs/params proc sys created");

	wq = create_singlethread_workqueue("async-del");
	atomic_set(&q_len, 0);
	atomic_set(&job_counter, 0);
	/*allocate dummy node for handling the list head*/
	ls_data = kmalloc(sizeof(struct work_data), GFP_KERNEL);
	if (!ls_data) {
		DEBUGMSG("dummy node addition failed");
		err = -ENOMEM;
	}
	ls_data->dentry = NULL;
	INIT_LIST_HEAD(&ls_data->node);
	INIT_DELAYED_WORK(&ls_data->work, work_handler);
	queue_delayed_work(wq, &ls_data->work, msecs_to_jiffies(1));
	DEBUGMSG("Dummy node scheduled");

out:
	if (err) {
		sgfs_destroy_inode_cache();
		sgfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_sgfs_fs(void)
{
	if (proc_sgfs) {
		remove_proc_entry("aq-status", proc_sgfs);
		remove_proc_entry("fs/sgfs", NULL);
	}
	if (message)
		kfree(message);

	if (sys_sgfs)
		unregister_sysctl_table(sys_sgfs);

	flush_workqueue(wq);
	destroy_workqueue(wq);
	UDBG;
	/*releasing dummy node*/
	DEBUGMSG("dummy node released");
	if (ls_data)
		kfree(ls_data);


	sgfs_destroy_inode_cache();
	sgfs_destroy_dentry_cache();
	unregister_filesystem(&sgfs_fs_type);
	pr_info("Completed sgfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Sgfs " SGFS_VERSION
		" (http://sgfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_sgfs_fs);
module_exit(exit_sgfs_fs);

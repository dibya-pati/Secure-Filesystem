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

#define SGCTL_UPDATEKEY _IOW('a', 1, int32_t*)
#define SGCTL_RECOVER _IO('b', 2)
#define SGCTL_RM _IO('c', 3)
#define SGCTL_PURGE _IO('d', 4)
#define SGCTL_CANCEL _IOW('e', 5, int32_t*)
extern struct workqueue_struct *wq;
struct dir_context *gctx = NULL;

struct list_head ls_head;
struct callback_ls {
	struct dir_context ctx;
	char *name;
};

struct fname_ls {
	char *ptr;//initial val: filename, after iteration: abs_filename
	long mtime;
	struct list_head fname_list;
};
/*
 * Initialize crypto values
 */
static int crypto_init(struct sdesc **sdescsha1, struct crypto_shash **sha1)
{
	int err_val = 0;
	unsigned int size;
	(*sha1) = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR((*sha1))) {
		DEBUGMSG("alloc fail\n");
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize((*sha1));
	(*sdescsha1) = kmalloc(size, GFP_KERNEL);
	if (!(*sdescsha1)) {
		err_val = -ENOMEM;
	}
	(*sdescsha1)->shash.tfm = (*sha1);
	(*sdescsha1)->shash.flags = 0x0;
	err_val = crypto_shash_init(&(*sdescsha1)->shash);
	if (err_val) {
		DEBUGMSG("Crypto init fail\n");
	}
	//printk("init done\n");
	return err_val;
}

/*dentry->d_name.namele_pathname module
 *retrieve from meta data file the original filename with path
 *<size>,<filepath+filename>,<compress_flag,enc_flag>_<time_string>_<keyid>_<uid>_<filename>
 *in the format
 *inputs:orig_filenamebuf: file name buf allocated by the caller
 *delete_filename:null terminated name for the deleted file
 *sb:struct super_blok pointer for sgfs
 *return:err
 */
static int retrieve_file_pathname(char *orig_filenamebuf, struct dentry *dentry)
{
	int err = 0;
	char *meta_filename = ".metadata";
	char *meta_fullfilename = NULL, *delfilename = NULL;
	struct file *meta_file_p = NULL;

	char origfile_len[5], deletedfile_len[5];//4 byte for size(max PATH_MAX)+null terminator
	char *orig_lenp = origfile_len;
	char *del_lenp = deletedfile_len;

	loff_t offset = 0, file_sz = 0, bytes = 0;
	long int o_filelen = 0, del_filelen = 0;

	meta_fullfilename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!meta_fullfilename) {
		err = -ENOMEM;
		goto out;
	}

	//err = get_rootpath(dentry->d_sb->s_root, &root_path);
	snprintf(meta_fullfilename, PATH_MAX, "%s/%s", root_pathname, meta_filename);

	meta_file_p = file_open(meta_fullfilename, O_RDONLY, 0666);
	if (!meta_file_p || IS_ERR(meta_file_p)) {
		err = PTR_ERR(meta_file_p);
		DEBUGMSG("meta file cant't be opened from reading");
		goto out;
	}
	file_sz = file_size(meta_file_p);

	delfilename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!delfilename) {
		err = -ENOMEM;
		goto out;
	}
	for (offset = 0; offset < file_sz; ) {
		bytes = file_read(meta_file_p, del_lenp,  4, offset);
		if (bytes != 4)
			break;

		offset += 4;
		del_lenp[bytes] = '\0';

		err = kstrtol(del_lenp, 10, &del_filelen);

		bytes = file_read(meta_file_p, orig_lenp, 4, offset);
		if (bytes != 4)
			break;

		offset += 4;
		orig_lenp[bytes] = '\0';

		err = kstrtol(orig_lenp, 10, &o_filelen);

		bytes = file_read(meta_file_p, delfilename,  del_filelen, offset);
		if (bytes != del_filelen)
			break;

		offset += del_filelen;
		delfilename[bytes] = '\0';

		if (!strcmp(delfilename, dentry->d_name.name)) {
			bytes = file_read(meta_file_p, orig_filenamebuf,  o_filelen, offset);
			if (bytes != o_filelen)
				break;
			orig_filenamebuf[bytes] = '\0';
			break;//first matching file exiting;
		}
		offset += o_filelen;
	}

out:
	if (meta_fullfilename)
		kfree(meta_fullfilename);
	if (delfilename)
		kfree(delfilename);
	if (meta_file_p)
		file_close(meta_file_p);
	return err;
}


/*
   gets key from the keyring
inputs:
retkeystr:return ketystring
sb: superblock pointer of the fs concerned
returns: keystring pointer
*/
int getKey(char **retkeystr, struct super_block *sb)
{
	//const struct cred *cred = current_cred();
	int err = 0;
	int idx;
	*retkeystr = NULL;
	for (idx = 0; idx < SGFS_SB(sb)->num_users; idx++) {

		/*if uid is matching return the keystr from the keyring*/
		// DEBUGINT(SGFS_SB_EDATA(SGFS_SB(sb),idx).uid.val);
		// DEBUGMSG(SGFS_SB_EDATA(SGFS_SB(sb),idx).keystr);
		// DEBUGINT(getuid_p()->val);
		if (!memcmp(&SGFS_SB_EDATA(SGFS_SB(sb), idx).uid, getuid_p(), sizeof(kuid_t))) {
			*retkeystr = SGFS_SB_EDATA(SGFS_SB(sb), idx).keystr;
			// DEBUGMSG(*retkeystr);
		}
	}
	if (!(*retkeystr))
		err = -EINVAL;

	return err;
}

/*
   add key to the keyring
inputs:
keystr: keystring of length 16
sb: pointer to the superblock for the fs concerned, Here refers to the upper fs sb pointer
mayneed a update key wrapper?
*/
static int putKey(char *keystr, struct super_block *sb)
{

	char *keystr_chk = NULL;
	int err = 0;
	int num_users = SGFS_SB(sb)->num_users;

	if (strlen(keystr) > MAX_KEYLEN-1) {
		err = -EINVAL;
		goto out;
	}
	err = getKey(&keystr_chk, sb);
	if (!err) {
		err = -EEXIST;
		goto out;
	} else if (err == -EINVAL) {
		/*key doesnt exist, reset the error from getkey*/
		err = 0;
	}

	/*not present in keyring, check if max users are reached else add*/
	if (num_users >= MAX_USERS - 1) {
		err = -ENOMEM;
		goto out;
	}

	/*copy the new data to keyring and update user count*/
	strcpy(SGFS_SB_EDATA(SGFS_SB(sb), num_users).keystr, keystr);
	memcpy((void *)&SGFS_SB_EDATA(SGFS_SB(sb), num_users).uid, (void *)getuid_p(), sizeof(kuid_t));
	SGFS_SB(sb)->num_users += 1;
out:
	return err;
}

/*
 * Open a file and try to return it's file pointer
 * returns NULL upon failure
 * returns *filep upon success
 */
struct file *file_open(const char *file_path, int flags, int mode)
{
	struct file *filep = NULL;
	mm_segment_t oldfs;

	oldfs = get_fs();
	set_fs(get_ds());
	filep = filp_open(file_path, flags, mode);
	set_fs(oldfs);
	if (!filep || IS_ERR(filep)) {
		return NULL;
	}

	return filep;
}

void file_close(struct file *filep)
{
	filp_close(filep, NULL);
}

/*
 * Read len bytes from file into buf, from offset
 * returns bytes succesfully read
 * returns 0 otherwise
 */
int file_read(struct file *filep, char *buf, int len, loff_t offset)
{
	mm_segment_t oldfs;
	int bytes;

	filep->f_pos = offset;
	oldfs = get_fs();
	set_fs(get_ds());
	bytes = vfs_read(filep, buf, len, &offset);
	//buf[bytes] = '\0';
	set_fs(oldfs);

	return bytes;
}

/*
 * Write to file
 * returns bytes
 */
int file_write(struct file *filep, char *buf, int len, loff_t offset)
{
	mm_segment_t oldfs;
	int bytes;

	oldfs = get_fs();
	set_fs(get_ds());
	bytes = vfs_write(filep, buf, len, &offset);
	set_fs(oldfs);

	return bytes;
}

int file_size(struct file *f)
{
	return f->f_inode->i_size;
}

static int get_is_compenc_from_filename(const unsigned char *filenamebuf, long *is_compenc)
{

	int err = 0;
	char is_compenc_buf[3];

	if (strlen(filenamebuf) < 31)
		return -EINVAL;
	strncpy(is_compenc_buf, filenamebuf, 2);
	is_compenc_buf[2] = '\0';
	// DEBUGMSG(is_compenc_buf);
	// DEBUGMSG(filenamebuf);

	err = kstrtol(is_compenc_buf, 10, is_compenc);
	// DEBUGINT(err);

	return err;

}

/*
 * Get absolute mount path from dentry
 */
int get_rootpath(struct dentry *dentry, char **abs_path)
{
	int err = 0;
	struct path lower_path;
	struct dentry *mnt_dentry, *lower_dentry;
	char *buffer_path = kmalloc(PATH_MAX, GFP_KERNEL);

	if (!buffer_path) {
		err = -ENOMEM;
		goto out;
	}

	mnt_dentry = dentry->d_sb->s_root;
	sgfs_get_lower_path(mnt_dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	*abs_path = dentry_path_raw(lower_dentry, buffer_path, PATH_MAX);
	sgfs_put_lower_path(mnt_dentry, &lower_path);

out:
	if (buffer_path)
		kfree(buffer_path);
	return 0;
}

int get_abspath(struct dentry *dentry, char **abs_path)
{
	int err = 0;
	char *buffer_path;
	struct path lower_path;
	struct dentry *lower_dentry;

	buffer_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buffer_path) {
		err = -ENOMEM;
		goto out;
	}
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	*abs_path = dentry_path_raw(lower_dentry, buffer_path, PATH_MAX);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	if (buffer_path)
		kfree(buffer_path);
	return 0;
}

/*
 * Calculate final hash value
 * updates hash value
 */
static int crypto_final(struct sdesc **sdescsha1, unsigned char *hash)
{
	int err_val;

	err_val = crypto_shash_final(&(*sdescsha1)->shash, hash);
	if (err_val) {
		printk("Crypto final fail\n");
	}
	return err_val;
}

/*
 * Wrapper for crypto hash function
 * updates hash value
 */
int get_sha1sum(char *buf, int len, char **hash)
{
	int err, i;
	unsigned char *o_hash = kmalloc(20*sizeof(char), GFP_KERNEL);
	struct sdesc *sdescsha1 = NULL;
	struct crypto_shash *sha1 = NULL;

	crypto_init(&sdescsha1, &sha1);
	err = crypto_shash_update(&sdescsha1->shash, buf, len);
	if (err) {
		printk("Crypto update fail\n");
	}
	crypto_final(&sdescsha1, o_hash);
	for (i = 0; i < 20; i++) {
		sprintf(*hash+(i*2), "%02x", o_hash[i]);
	}
	kfree(o_hash);
	kfree(sdescsha1);
	return err;
}

static ssize_t sgfs_read(struct file *file, char __user *buf,
		size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
				file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
				file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
				file_inode(lower_file));
	}

	return err;
}

static int filldir_ls(struct dir_context *ctx, const char *name, int len, loff_t pos, u64 ino, unsigned int d_type)
{
	int ret = 0;
	struct fname_ls *cur = (struct fname_ls *)kmalloc(sizeof(struct fname_ls), GFP_KERNEL);

	cur->ptr = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (!cur->ptr)
		return -ENOMEM;
	//discard [.] [..] files returned by filldir_ls
	if (!(strcmp(name, ".")) || !(strcmp(name, "..")))
		return 0;
	strcpy(cur->ptr, name);
	list_add(&cur->fname_list, &ls_head);

	return ret;
}

static int sgfs_filldir(struct dir_context *ctx, const char *lower_name,
		 int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	const struct cred *cred = current_cred();
	char uid[5];
	snprintf (uid, 5,"%04d",cred->uid.val);
	uid[4]='\0';
	if ((!strcmp(uid,"0000")) || (lower_namelen > 6 &&\
			!strncmp(uid,lower_name+3,4))){
	
			return gctx->actor(gctx, lower_name, lower_namelen, offset, ino, d_type);
 
	}
	return 0;
}



static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
/*	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)	*/	/* copy the atime */
	//	fsstack_copy_attr_atime(d_inode(dentry),
	//			file_inode(lower_file));
//	return err;
 	int err;
 	struct file *lower_file = NULL;
 	struct dentry *dentry = file->f_path.dentry;
	struct dir_context ctxu = {
		.actor = sgfs_filldir,
		.pos = ctx->pos,
	};
	gctx = ctx;
	
	if (!strcmp(dentry->d_iname,".sg") &&\
			!strcmp(dentry->d_parent->d_iname,"/")){

		DEBUGMSG("Running in sg folder");
		lower_file = sgfs_lower_file(file);
		err = iterate_dir(lower_file, &ctxu);
		file->f_pos = lower_file->f_pos;
		if (err >= 0)		/* copy the atime */
			fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	}
	else{
		lower_file = sgfs_lower_file(file);
		err = iterate_dir(lower_file, ctx);
		file->f_pos = lower_file->f_pos;
		if (err >= 0)		/* copy the atime */
			fsstack_copy_attr_atime(d_inode(dentry),
 					file_inode(lower_file));
	}

	gctx = NULL;	
 	return err;
}

static int decompress_file(struct file *inp, struct file *out)
{
	int err = 0;
	int offset = 0, offset_wr = 0, bytes, file_sz = file_size(inp), data_len;
	long int_sz;
	unsigned char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	char *data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	char hex_sz[5];
	struct crypto_comp *tfm = crypto_alloc_comp("deflate", 0, 0);

	if (!tfm) {
		DEBUGMSG("Dangerous: Compress tfm alloc");
		goto out;
	}

	for (offset = 0; offset < file_sz; ) {
		bytes = file_read(inp, hex_sz, 4, offset);
		offset += 4;
		hex_sz[bytes] = '\0';
		err = kstrtol(hex_sz, 16, &int_sz);
		memset(buf, '\0', chnk_sz);
		bytes = file_read(inp, buf, int_sz, offset);
		offset += int_sz;
		if (int_sz != bytes) {
			DEBUGMSG("Dangerous: compress data read mismatch");
		}
		data_len = chnk_sz;
		err = crypto_comp_decompress(tfm, buf, bytes, data, &data_len);
		data[data_len] = '\0';

		file_write(out, data, data_len, offset_wr);
		offset_wr += data_len;
	}
out:
	if (buf)
		kfree(buf);
	if (data)
		kfree(data);
	DEBUGINT(err);
	DEBUGMSG("Success: Decompress");
	return err;
}

static int recover(struct file *inp_file, char *out_path, char *key)
{
	int err = 0;
	long flag = 0;
	int flag_encrypt = 0, flag_compress = 0;
	struct file *out_file = NULL;

	out_file = file_open(out_path, O_TRUNC|O_CREAT|O_WRONLY, 0777);
	if (!out_file) {
		DEBUGMSG("Dangerous: Output file create fail");
		err = PTR_ERR(out_file);
		goto out;
	}

	err = get_is_compenc_from_filename(inp_file->f_path.dentry->d_name.name, &flag);
	flag_encrypt = flag/10;
	flag_compress = flag%10;

	if (flag_encrypt == 0 && flag_compress == 0) {
		err = copy_file_plaintext(inp_file, out_file);
	} else if (flag_encrypt == 0 && flag_compress == 1) {
		err = decompress_file(inp_file, out_file);
	} else if (flag_encrypt == 1 && flag_compress == 0) {
		err = decrypt_file(inp_file, out_file, key);
	} else if (flag_encrypt == 1 && flag_compress == 1) {
		err = decrypt_decompress_file(inp_file, out_file, key);
	}

out:
	if (out_file)
		file_close(out_file);
	if (err)
		DEBUGMSG("Fail: Recover");
	else
		DEBUGMSG("Success: Recover");
	return err;
}



static int cmp_ls(void *priv, struct list_head *a, struct list_head *b)
{
	struct fname_ls *f_a = container_of(a, struct fname_ls, fname_list);
	struct fname_ls *f_b = container_of(b, struct fname_ls, fname_list);

	return f_a->mtime < f_b->mtime;
}

int iterate(int who)
{
	int err = 0;
	int f_co = 0;
	char *name = kmalloc(PATH_MAX, GFP_KERNEL);
	char *f_name = NULL;
	char *mnt_path = NULL;
	struct file *file = NULL;
	struct file *tmp_file = NULL;
	struct fname_ls *entry;
	struct list_head *ptr;
	struct dentry *f_dentry = NULL;
	const struct cred *cred = current_cred();
	char uid[5];

	struct callback_ls buffer = {
		.ctx.actor = filldir_ls,
		.name = name,
	};
	if (!name) {
		err = -ENOMEM;
		goto out;
	}
	f_name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!f_name) {
		err = -ENOMEM;
		goto out;
	}
	mnt_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!mnt_path) {
		err = -ENOMEM;
		goto out;
	}
	strcpy(mnt_path, root_pathname);

	file = file_open(strcat(mnt_path, "/.sg"), O_RDONLY, 0777);
	if (IS_ERR_OR_NULL(file)) {
		err = PTR_ERR(file);
		DEBUGINT(err);
		DEBUGMSG("Fail: Could not open mnt_path file");
		goto out;
	}

	INIT_LIST_HEAD(&ls_head);
	err = iterate_dir(file, &buffer.ctx);
	if (err)
		goto out;

	if (!file->f_path.dentry) {
		UDBG;
		goto out;
	}

	list_for_each(ptr, &ls_head) {
		entry = list_entry(ptr, struct fname_ls, fname_list);

		snprintf(f_name, PATH_MAX, "%s/%s", mnt_path, entry->ptr);

		tmp_file = file_open(f_name, O_RDONLY, 0777);
		if (IS_ERR_OR_NULL(tmp_file)) {
			err = PTR_ERR(tmp_file);
			goto out;
		}

		strcpy(entry->ptr, f_name);
		entry->mtime = tmp_file->f_path.dentry->d_inode->i_mtime.tv_sec;
		
		file_close(tmp_file);
	}

	if (who == 0) {
		list_sort(NULL, &ls_head, cmp_ls);

		list_for_each(ptr, &ls_head) {
			f_co++;
			entry = list_entry(ptr, struct fname_ls, fname_list);
			if (f_co > sgfs_params.max_files.val) {
				tmp_file = file_open(entry->ptr, O_RDONLY, 0777);
				f_dentry = tmp_file->f_path.dentry;
				err = vfs_unlink(d_inode(f_dentry->d_parent), f_dentry, NULL);
				if (tmp_file)
					file_close(tmp_file);
			}
		}
	}
	else if(who == 1) {
		snprintf (uid, 5,"%04d",cred->uid.val);
		uid[4]='\0';
		
		list_for_each(ptr, &ls_head) {
			
			entry = list_entry(ptr, struct fname_ls, fname_list);
			if ((!strcmp(uid,"0000")) || ((int)(strlen(entry->ptr)) > strlen(mnt_path)+4 +4+4 &&\
						!strncmp(uid,entry->ptr+strlen(mnt_path)+4,4))) {
				//DEBUGMSG(entry->ptr+strlen(mnt_path)+4);
				tmp_file = file_open(entry->ptr, O_RDONLY, 0777);
				f_dentry = tmp_file->f_path.dentry;
				err = vfs_unlink(d_inode(f_dentry->d_parent), f_dentry, NULL);
				if (tmp_file)
					file_close(tmp_file);

			}
		}
	}

	/*To-do: free name in list, list*/
out:
	if (name)
		kfree(name);
	if (f_name)
		kfree(f_name);
	if (file)
		file_close(file);
	if (err)
		DEBUGMSG("Fail: Iterate");
	return err;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct work_data *data;
	long err = -ENOTTY;
	struct file *lower_file = NULL;
	char keystr[MAX_KEYLEN];
	char *key = NULL;
	char *filenamebuf = NULL;
	int comp = 0, enc = 0, ret = 0;
	struct dentry *dentry = file->f_path.dentry;
	int iters = 0;
	struct list_head *itr = NULL;
	struct work_data *wd = NULL;
	int found = 0;
	lower_file = sgfs_lower_file(file);

	if (cmd == SGCTL_UPDATEKEY) {
		err = copy_from_user(keystr, (char *) arg, MAX_KEYLEN);
		//DEBUGMSG(keystr);
		/*check if exists in persitent and match then if not existent write to both*/
		err = rw_keyring(file_inode(file)->i_sb, keystr, 0);
		if (err < 0) {
			DEBUGINT((int)err);
			goto out;
		}
		err = 0;
		err = putKey(keystr, file_inode(file)->i_sb);
	} else if (cmd == SGCTL_RECOVER) {
		DEBUGMSG("recover ioctl");
		filenamebuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!filenamebuf) {
			err = -ENOMEM;
			goto out;
		}

		err = retrieve_file_pathname(filenamebuf, file->f_path.dentry);
		if (err)
			goto out;

		/* To-do: Change to get_keyid_from_filename */
		err = getKey(&key, file->f_path.dentry->d_sb);
		if (err)
			goto out;

		err = recover(file, filenamebuf, key);
		if (err)
			goto out;
		
		err = sgfs_unlink_default(d_inode(dentry->d_parent), dentry);
		goto out;
	} else if (cmd == SGCTL_CANCEL) {
		DEBUGINT2("Attempting job cancel for:",(int)arg);
	/*Iterate list head and set cancel_job to 0*/
		spin_lock(&qlock);		
		list_for_each(itr, &ls_data->node) {
               		wd = list_entry(itr, struct work_data, node);
                	if (wd && wd->dentry) 
				if ((int)arg == wd->job_id){
					DEBUGINT2("job removed from queue",wd->job_id);
					found = 1;
					atomic_set(&wd->cancel_job, 1);
				}
		}
		spin_unlock(&qlock);
		if (!found){
			err = -EINVAL;
			goto out;
		}

	} else if (cmd == SGCTL_RM) {
		comp = (current->sgfs_flag & CLONE_DETACHED) ? 1:0;
		enc = (current->sgfs_flag & CLONE_PROT) ? 1:0;
		if ((file_size(lower_file) < 4096) || (0==sgfs_params.queue_len.val)) {
			err = unlink_process(dentry, enc, comp);
		 	if (err){
				DEBUGMSG("Unlink process failed for small file");
				goto out;
			}	
			err = vfs_unlink(d_inode(dentry->d_parent), dentry, NULL);
			if (err){
				DEBUGMSG("Failed small file deletion");
				goto out;
			}
		} else{
			data = kmalloc(sizeof(struct work_data), GFP_KERNEL);
			if (!data) {
				DEBUGMSG("Dangerous: work_data malloc");
				err = -ENOMEM;
				goto out;
			}
			iters = 0;
			while (iters < 50) {
				if (atomic_inc_return(&q_len) >= sgfs_params.queue_len.val) {
					mdelay(50);
					atomic_dec(&q_len);
					iters++;
				} else{
					break;
				}
			}
			if (iters == 50) {
				DEBUGMSG2("FAILED Deletion!", dentry->d_name.name);
				err = -EBUSY;
				if (data)
					kfree(data); // Otherwise handled in work_handler
				goto out;
			}

			spin_lock(&qlock);
			data->job_id = atomic_inc_return(&job_counter);
			atomic_set(&data->cancel_job, 0);
			list_add(&data->node, &ls_data->node);
			getnstimeofday(&data->ts);
			INIT_DELAYED_WORK(&data->work, work_handler);
		/*	if(!dentry){
				DEBUGMSG("Dangerous!Dentry failed");
				goto out;
			}*/
			data->dentry = dentry;
			data->flag_compress = comp;
			data->flag_encrypt = enc;

			ret = queue_delayed_work(wq, &data->work, msecs_to_jiffies(5));
			if (ret == 0) {
				DEBUGMSG("Already present in queue");
			}
			/*returns queued job_id to the user*/
			err = data->job_id;
			spin_unlock(&qlock);
		}
	} else if (cmd == SGCTL_PURGE) {
		//DEBUGMSG(file->f_path.dentry->d_name.name);
		err = iterate(1);
		if (err)
			goto out;
	}

	/* XX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				file_inode(lower_file));
	err = 0;
	/*if (cmd == SGCTL_RECOVER) {
		err = sgfs_unlink_default(d_inode(dentry->d_parent), dentry);
		DEBUGINT((int)err);
	}*/

out:
	if (filenamebuf)
		kfree(filenamebuf);
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
		int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
	ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
				file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
	ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
				file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
				file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};

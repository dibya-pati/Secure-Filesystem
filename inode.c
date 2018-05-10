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
#include <linux/time.h>

int chnk_sz = 2048;

static int sgfs_create(struct inode *dir, struct dentry *dentry,
		umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	if ((!strcmp(dentry->d_parent->d_iname, ".sg") ||\
        		strcmp(dentry->d_parent->d_parent->d_iname, "/"))){
		err = -EPERM;
		goto out;
	} 
	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
			lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
			sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

/*write_file_meta module
 *wrties to meta data file with the original and deleted filanames
 *<size>,<filepath+filename>,<compress_flag,enc_flag>_<time_string>_<keyid>_<uid>_<filename>
 *in the format
 *inputs:orig_filename: null terminated name for the original file
 *delete_filename:null terminated name for the deleted file
 *sb:struct super_blok pointer for sgfs
 *return:err
 */
static int write_file_meta(char *orig_filename, char *delete_filename, struct super_block *sb)
{

	int err = 0;
	char *meta_filename = ".metadata";
	char *file_name_meta = NULL;
	struct file *meta_file_p = NULL;
	char sizebuf[9];//4 byte for size(max PATH_MAX)+one null termination

	file_name_meta = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!file_name_meta) {
		err = -ENOMEM;
		goto out;
	}

	/*err = get_rootpath(sb->s_root, &root_path);
	if (err || !root_path) {
		goto out;
	}*/
	snprintf(file_name_meta, PATH_MAX, "%s/%s", root_pathname, meta_filename);
	meta_file_p = file_open(file_name_meta, O_APPEND|O_WRONLY, 0666);
	if (!meta_file_p || IS_ERR(meta_file_p)) {
		DEBUGMSG("meta file cant't be opened from writing/appending");
		err = PTR_ERR(meta_file_p);
		goto out;
	}

	snprintf(sizebuf, 9, "%04d%04d", (int)strlen(delete_filename), (int)strlen(orig_filename));

	file_write(meta_file_p, sizebuf, 8, meta_file_p->f_pos);
	file_write(meta_file_p, delete_filename, strlen(delete_filename), meta_file_p->f_pos);
	file_write(meta_file_p, orig_filename, strlen(orig_filename), meta_file_p->f_pos);

out:
	if (file_name_meta)
		kfree(file_name_meta);
	if (meta_file_p)
		file_close(meta_file_p);

	return 0;

}

/*
   gets key from the keyring
inputs:
retkeystr:return ketystring
sb: superblock pointer of the fs concerned
returns: keyid, >0 no error else error
*/
static uid_t get_key_id(struct super_block *sb)
{
	//const struct cred *cred = current_cred();
	uid_t err = 0;
	int idx = 0;

	for (idx = 0; idx < SGFS_SB(sb)->num_users; idx++) {

		/*if uid is matching return the keystr from the keyring*/
		//DEBUGINT(SGFS_SB_EDATA(SGFS_SB(sb),idx).uid.val);
		//DEBUGMSG(SGFS_SB_EDATA(SGFS_SB(sb),idx).keystr);

		if (!memcmp(&SGFS_SB_EDATA(SGFS_SB(sb), idx).uid, getuid_p(), sizeof(kuid_t)))
			return SGFS_SB_EDATA(SGFS_SB(sb), idx).uid.val;
	}

	err = SGFS_SB_EDATA(SGFS_SB(sb), 0).uid.val;
	return err;//return 0, default key

}

/*create filename of the type
 *<size>,<filepath+filename>,<compress_flag,enc_flag>_<uid>_<keyid>_<time_string>_<filename>
 *<compress_flag,enc_flag>_<time_string>_<keyid>_<uid>_name
 *inputs:
 *filenamebuf:malloced buf to be provided by the user, computed name to be filled in this
 *dentry:dentry of sgfs file system
 *is_compressed:plan to compress
 *is_encrypted:plan to encrypt
 *return:
 *err
 */
static int make_filename(char *filenamebuf, struct dentry *dentry,\
		int is_compressed, int is_encrypted)
{
	int err = 0;
	struct tm tm;
	struct timespec ts;
	uid_t keyid_val = get_key_id(dentry->d_sb);
	uid_t cur_uid_val = current_cred()->uid.val;

	getnstimeofday(&ts);
	time_to_tm(ts.tv_sec, 0, &tm);
	snprintf(filenamebuf+strlen(filenamebuf), 31,\
			"%01d%01d_%04d_%04d_%04ld-%02d-%02d-%02d:%02d_",\
			is_compressed, is_encrypted, cur_uid_val,\
			keyid_val, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,\
			tm.tm_hour, tm.tm_min);

	strcat(filenamebuf, dentry->d_name.name);
	// DEBUGMSG(filenamebuf);

	return err;
}

static void crypto_req_done(struct crypto_async_request *req, int err)
{
	struct crypto_wait *wait = req->data;

	if (err == -EINPROGRESS)
		return;

	wait->err = err;
	complete(&wait->completion);
}

static inline int crypto_wait_req(int err, struct crypto_wait *wait)
{
	switch (err) {
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&wait->completion);
		reinit_completion(&wait->completion);
		err = wait->err;
		break;
	};

	return err;
}

static inline void crypto_init_wait(struct crypto_wait *wait)
{
	init_completion(&wait->completion);
}

static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
		int enc)
{
	int rc;

	if (enc)
		rc = crypto_wait_req(crypto_skcipher_encrypt(sk->req), &sk->wait);
	else
		rc = crypto_wait_req(crypto_skcipher_decrypt(sk->req), &sk->wait);
	if (rc)
		printk("skcipher encrypt returned with result %d\n", rc);
	return rc;
}

/*
 * Ref: https://01.org/linuxgraphics/gfx-docs/drm/crypto/api-samples.html
 */
/* Initialize and trigger cipher operation */
static int skcipher(unsigned char **scratchpad, int enc, int chnk_sz, unsigned char *key)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	// unsigned char key[33];
	int ret = -EFAULT;

	skcipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(skcipher)) {
		printk("could not allocate skcipher handle\n");
		return PTR_ERR(skcipher);
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		printk("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &sk.wait);

	/* AES 256 with random key */
	// get_random_bytes(&key, 32);

	if (crypto_skcipher_setkey(skcipher, key, (int)strlen(key))) {
		printk("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	/* IV will be random */
	ivdata = kmalloc(16, GFP_KERNEL);
	if (!ivdata) {
		printk("could not allocate ivdata\n");
		goto out;
	}
	// get_random_bytes(ivdata, 16);
	memcpy(ivdata, ":_encrypt_ivdatab", 16);

	sk.tfm = skcipher;
	sk.req = req;

	/* We encrypt one block */
	sg_init_one(&sk.sg, (*scratchpad), chnk_sz);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, chnk_sz, ivdata);
	crypto_init_wait(&sk.wait);

	/* encrypt data */
	ret = test_skcipher_encdec(&sk, enc);
	if (ret)
		goto out;

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	kfree(ivdata);
	return ret;
}

int copy_file_plaintext(struct file *inp, struct file *out)
{
	int err = 0;
	int offset, bytes, file_sz = file_size(inp);
	char *buf = kmalloc(chnk_sz*sizeof(char), GFP_KERNEL);

	if (!buf) {
		err = -ENOMEM;
		DEBUGMSG("Dangerous: memory");
		goto out;
	}

	for (offset = 0; offset < file_sz; offset += chnk_sz) {
		memset(buf, '\0', chnk_sz);
		bytes = file_read(inp, buf, chnk_sz, offset);
		if (bytes != chnk_sz)
			buf[bytes] = '\0';
		file_write(out, buf, bytes, offset);
	}
out:
	if (buf)
		kfree(buf);
	if (err)
		DEBUGMSG("Fail: Copy plaintext");
	else
		DEBUGMSG("Success: Copy plaintext");
	return err;
}

static int compress_file(struct file *inp, struct file *out)
{
	int err = 0;
	loff_t offset = 0, offset_wr = 0, bytes, file_sz = file_size(inp);
	unsigned int data_len = 0;
	unsigned char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	char *data = NULL, hex_sz[5];
	struct crypto_comp *tfm = crypto_alloc_comp("deflate", 0, 0);

	data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}
	if (!tfm) {
		DEBUGMSG("Dangerous: Compress tfm alloc");
		goto out;
	}

	for (offset = 0; offset < file_sz; offset += chnk_sz) {
		memset(buf, '\0', chnk_sz);
		bytes = file_read(inp, buf, chnk_sz, offset);
		data_len = chnk_sz;
		err = crypto_comp_compress(tfm, buf, bytes, data, &data_len);
		data[data_len] = '\0';
		snprintf(hex_sz, 5, "%04x", data_len);

		file_write(out, hex_sz, 4, offset_wr);
		offset_wr += 4;
		file_write(out, data, data_len, offset_wr);
		offset_wr += data_len;
	}
UDBG;
out:
	if (buf)
		kfree(buf);
	if (data)
		kfree(data);
	if (err)
		DEBUGMSG("Fail: Compress");
	else
		DEBUGMSG("Success: Compress");
	return err;
}

int encrypt_file(struct file *inp, struct file *out, char *key)
{
	int err = 0;
	int offset, bytes, file_sz = file_size(inp);
	unsigned char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto out;
	}

	for (offset = 0; offset < file_sz; offset += chnk_sz) {
		memset(buf, '\0', PAGE_SIZE);
		bytes = file_read(inp, buf, chnk_sz, offset);
		err = skcipher(&buf, 0, chnk_sz, key);
		
		if (err < 0) {
			goto out;
		}
		file_write(out, buf, chnk_sz, offset);
	}
out:
	if (buf)
		kfree(buf);
	if (err)
		DEBUGMSG("Fail: Encryption");
	else
		DEBUGMSG("Success: Encryption");
	return err;
}

int encrypt_compress_file(struct file *inp, struct file *out, char *key)
{
	int err = 0;
	int offset, offset_wr = 0, bytes, file_sz = file_size(inp);
	unsigned int data_len = 0, mod_len = 0;
	unsigned char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	unsigned char *data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	char hex_sz[5];
	struct crypto_comp *tfm = crypto_alloc_comp("deflate", 0, 0);

	if (!tfm) {
		DEBUGMSG("Dangerous: Compress tfm alloc");
		goto out;
	}

	for (offset = 0; offset < file_sz; offset += chnk_sz) {
		memset(buf, '\0', PAGE_SIZE);
		memset(data, '\0', PAGE_SIZE);
		bytes = file_read(inp, buf, chnk_sz, offset);

		data_len = chnk_sz;
		err = crypto_comp_compress(tfm, buf, bytes, data, &data_len);

		if (data_len%16 != 0)
			mod_len = ((data_len/16) + 1)*16;
		else
			mod_len = data_len;

		snprintf(hex_sz, 5, "%04x", mod_len);

		err = skcipher(&data, 0, mod_len, key);
		if (err < 0) {
			goto out;
		}

		file_write(out, hex_sz, 4, offset_wr);
		offset_wr += 4;
		file_write(out, data, mod_len, offset_wr);
		offset_wr += mod_len;
	}
out:
	if (buf)
		kfree(buf);
	if (data)
		kfree(data);
	if (err)
		DEBUGMSG("Fail: Encryption-Compression");
	else
		DEBUGMSG("Success: Encryption-Compression");
	return err;
}

int decrypt_decompress_file(struct file *inp, struct file *out, char *key)
{
	int err = 0;
	int offset = 0, offset_wr = 0, bytes = 0, file_sz = file_size(inp), data_len;
	long int_sz;
	unsigned char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	unsigned char *data = kmalloc(PAGE_SIZE, GFP_KERNEL);
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
		memset(data, '\0', chnk_sz);
		bytes = file_read(inp, buf, int_sz, offset);
		offset += int_sz;
		if (int_sz != bytes) {
			DEBUGMSG("Dangerous: compress data read mismatch");
		}

		err = skcipher(&buf, 1, int_sz, key);
		if (err < 0) {
			goto out;
		}

		data_len = chnk_sz;
		err = crypto_comp_decompress(tfm, buf, int_sz, data, &data_len);

		file_write(out, data, data_len, offset_wr);
		offset_wr += data_len;
	}
out:
	if (buf)
		kfree(buf);
	if (data)
		kfree(data);
	DEBUGINT(err);
	if (err)
		DEBUGMSG("Fail: Decryption-Decompression");
	else
		DEBUGMSG("Success: Decryption-Decompression");
	return err;
}

int decrypt_file(struct file *inp, struct file *out, char *key)
{
	int err = 0;
	int offset, bytes, file_sz = file_size(inp);
	unsigned char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	for (offset = 0; offset < file_sz; offset += chnk_sz) {
		memset(buf, '\0', chnk_sz);
		bytes = file_read(inp, buf, chnk_sz, offset);
		err = skcipher(&buf, 1, chnk_sz, key);
		if (err < 0) {
			goto out;
		}
		file_write(out, buf, (int)strlen(buf), offset);
	}
out:
	if (buf)
		kfree(buf);
	if (err)
		DEBUGMSG("Fail: Decryption");
	else
		DEBUGMSG("Success: Decryption");
	return err;
}

/*
 * Input: To delete file dentry
 * Input: Flag encrypt (1/0)
 * Input: Flag compress (1/0)
 * Output: 0 upon success
 */
int unlink_process(struct dentry *dentry, int flag_encrypt, int flag_compress)
{
	int err = 0;
	//char *inp_path = NULL,
	char *out_fname = NULL, *out_path = NULL;
	struct file *inp_file = NULL, *out_file = NULL;
	char *key = NULL;
	char  *tmp = NULL;
	char *inp_path = NULL;
	struct path lower_path;
	struct dentry *lower_dentry = NULL, *lower_dir_dentry = NULL;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	out_fname = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!out_fname) {
		DEBUGMSG("Dangerous: memory");
		err = -ENOMEM;
		goto out;
	}
	out_path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!out_path) {
		DEBUGMSG("Dangerous: memory");
		err = -ENOMEM;
		goto out;
	}

	err = make_filename(out_fname, dentry, flag_encrypt, flag_compress);
	if (err) {
		UDBG;
		goto out;
	}
	snprintf(out_path, PATH_MAX, "%s/.sg/%s", root_pathname, out_fname);

	tmp = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!tmp) {
		err = -ENOMEM;
		goto out;
	}
	inp_path = d_path(&lower_path, tmp, PATH_MAX);
	if (IS_ERR_OR_NULL(inp_path)) {
		goto out;
	}

	err = write_file_meta(inp_path, out_fname, dentry->d_sb);
	if (err) {
		DEBUGINT(err);
		goto out;
	}

	inp_file = file_open(inp_path, O_RDONLY, 0777);
	if (!inp_file || IS_ERR(inp_file)) {
		err = PTR_ERR(inp_file);
		UDBG;
		goto out;
	}
	out_file = file_open(out_path, O_CREAT|O_WRONLY, 0777);
	if (!out_file || IS_ERR(out_file)) {
		err = PTR_ERR(out_file);
		UDBG;
		goto out;
	}
	err = getKey(&key, dentry->d_sb);
	if (err == -EINVAL) {
		err = 0;
		key = SGFS_SB_EDATA(SGFS_SB(dentry->d_sb), 0).keystr;
	}

	if (flag_encrypt == 0 && flag_compress == 0) {
		err = copy_file_plaintext(inp_file, out_file);
	} else if (flag_encrypt == 0 && flag_compress == 1) {
		err = compress_file(inp_file, out_file);
	} else if (flag_encrypt == 1 && flag_compress == 0) {
		err = encrypt_file(inp_file, out_file, key);
	} else if (flag_encrypt == 1 && flag_compress == 1) {
		err = encrypt_compress_file(inp_file, out_file, key);
	}
	fsstack_copy_attr_all(out_file->f_inode, inp_file->f_inode);
	//fsstack_copy_inode_size(out_file->f_inode, inp_file->f_inode);
out:
	if (tmp)
		kfree(tmp);
	if (out_fname)
		kfree(out_fname);
	if (out_path)
		kfree(out_path);
	if (inp_file)
		file_close(inp_file);
	if (out_file)
		file_close(out_file);

	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry = NULL;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
			sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */

out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);

	if (err)
		DEBUGMSG("Fail: Unlink");
	else
		DEBUGMSG("Success: Unlink");
	return err;
}

int sgfs_unlink_default(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(d_inode(dentry),
			sgfs_lower_inode(d_inode(dentry))->i_nlink);
	d_inode(dentry)->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */

out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	if (err)
		DEBUGMSG("Fail: Unlink default");
	else
		DEBUGMSG("Success: Unlink default");
	return err;
}

static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);
	if ((!strcmp(dentry->d_parent->d_iname, ".sg") ||\
                                strcmp(dentry->d_parent->d_parent->d_iname, "/"))){
		err = -EPERM;
		goto out;
	} 
	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			d_inode(lower_new_dir_dentry), lower_new_dentry,
			NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
				d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
			!d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
			buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
		struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

	static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

	static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
			d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

	static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
			d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

	static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
			!d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

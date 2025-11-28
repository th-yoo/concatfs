/*
  FUSE: Filesystem in Userspace

  Copyright 2015 Peter Schlaile (peter at schlaile dot de)
  Copyright 2025 th-yoo - gzip decompression support

  Files with the string "-concat-" anywhere in the filename are considered
  concatenation description special files.

  They contain a file list, which, when mounted as a fuse file system
  will turn these files into concatenations of the contents of the
  contained files.

  e.g.

  file1.MTS
  file2.MTS
  file3.MTS

  bigmovie-concat-file.MTS

  contents of bigmovie-concat-file.MTS:

  file1.MTS
  file2.MTS
  file3.MTS

  on seperate lines. Empty lines or lines, which do not resolve to a file where
  a stat call succeeds, are ignored.

  Gzip-compressed files (.gz) are automatically detected and decompressed
  transparently during sequential reads.

  gcc -Wall concatfs.c `pkg-config fuse --cflags --libs` -lz -o concatfs
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <zlib.h>

static char src_dir[PATH_MAX];

struct chunk {
	struct chunk * next;
	pthread_mutex_t lock;  /* protects gzip state for thread safety */

	int fd;
	off_t fsize;        /* uncompressed size for gzip, actual size otherwise */
	int is_gzip;        /* 1 if this chunk is a gzip file */
	gzFile gzfd;        /* zlib file handle for gzip files */
	off_t gz_pos;       /* current read position in uncompressed stream */
};

struct concat_file {
	struct concat_file * next;
	struct chunk * chunks;

	int fd;
	off_t fsize;
	int refcount;
};

static struct concat_file * open_files = 0;
static pthread_mutex_t  the_lock;

static void lock()
{
	pthread_mutex_lock(&the_lock);
}

static void unlock()
{
	pthread_mutex_unlock(&the_lock);
}

/* Build full path from src_dir and relative path.
   Returns 0 on success, -ENAMETOOLONG if path would be truncated. */
static int make_path(char *dest, size_t dest_size, const char *base, const char *path)
{
	int len = snprintf(dest, dest_size, "%s/%s", base, path);
	if (len < 0 || (size_t)len >= dest_size) {
		return -ENAMETOOLONG;
	}
	return 0;
}

/* Check if file is gzip by reading magic bytes (0x1f 0x8b) */
static int is_gzip_file(int fd)
{
	unsigned char magic[2];
	if (pread(fd, magic, 2, 0) == 2) {
		return (magic[0] == 0x1f && magic[1] == 0x8b);
	}
	return 0;
}

/* Get uncompressed size from gzip trailer (last 4 bytes).
   Note: This is modulo 2^32, so files >4GB will report incorrect size. */
static off_t get_gzip_uncompressed_size(int fd, off_t compressed_size)
{
	unsigned char buf[4];
	uint32_t size;

	if (pread(fd, buf, 4, compressed_size - 4) != 4) {
		return compressed_size; /* fallback to compressed size */
	}

	/* Little-endian 32-bit value */
	size = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	return (off_t)size;
}

static struct concat_file * open_files_find(int fd)
{
	struct concat_file * cf;

	lock();

	for (cf = open_files; cf; cf = cf->next) {
		if (cf->fd == fd) {
			unlock();
			return cf;
		}
	}
	
	unlock();

	return 0;
}

static void open_files_push_front(struct concat_file * cf)
{
	lock();

	cf->next = open_files;
	open_files = cf;

	unlock();
}

static struct concat_file * open_files_erase(int fd)
{
	struct concat_file * rv = 0;
	struct concat_file * p;

	lock();

	if (open_files && open_files->fd == fd) {
		rv = open_files;
		open_files = rv->next;
	} else {
		for (p = open_files; p; p = p->next) {
			if (p->next && p->next->fd == fd) {
				break;
			}
		}

		if (p) {
			rv = p->next;
			p->next = p->next->next;
		}
	}

	if (rv) {
		rv->next = 0;
	}

	unlock();

	return rv;
}

static struct concat_file * open_concat_file(int fd, const char * path)
{
	struct concat_file * rv = 0;
	char bpath[PATH_MAX+1];
	char fpath[PATH_MAX+1];
	char * base_dir;
	struct stat stbuf;
	struct chunk * c = 0;
	
	FILE * fp;

	if (fd >= 0) {
		fp = fdopen(dup(fd), "r");
	} else {
		fp = fopen(path, "r");
	}

	if (!fp) {
		return 0;
	}

	rv = (struct concat_file *) calloc(sizeof(struct concat_file), 1);
	strncpy(bpath, path, sizeof(bpath));

	base_dir = dirname(bpath);

	fpath[PATH_MAX] = 0;
	bpath[PATH_MAX] = 0;

	rv->fd = fd;
	rv->refcount = 1;

	while (fgets(fpath, sizeof(fpath), fp)) {
		char tpath[PATH_MAX];
		struct chunk * c_n;
		int chunk_fd;
		off_t chunk_size;

		fpath[strlen(fpath) - 1] = 0;

		if (fpath[0] == '/') {
			strncpy(tpath, fpath, sizeof(tpath));
			tpath[sizeof(tpath) - 1] = '\0';
		} else {
			if (make_path(tpath, sizeof(tpath), base_dir, fpath) != 0)
				continue;
		}
		if (stat(tpath, &stbuf) != 0) {
			continue;
		}

		/* Open chunk file to check if it's gzip */
		chunk_fd = open(tpath, O_RDONLY);
		if (chunk_fd < 0) {
			continue;
		}

		c_n = (struct chunk *) calloc(sizeof(struct chunk), 1);
		pthread_mutex_init(&c_n->lock, NULL);
		c_n->fd = chunk_fd;
		c_n->is_gzip = is_gzip_file(chunk_fd);

		if (c_n->is_gzip) {
			/* Get uncompressed size from gzip trailer */
			chunk_size = get_gzip_uncompressed_size(chunk_fd, stbuf.st_size);
			c_n->fsize = chunk_size;
			c_n->gz_pos = 0;

			if (fd >= 0) {
				/* Open gzip handle for decompression */
				c_n->gzfd = gzdopen(dup(chunk_fd), "rb");
				if (!c_n->gzfd) {
					close(chunk_fd);
					free(c_n);
					continue;
				}
			}
		} else {
			chunk_size = stbuf.st_size;
			c_n->fsize = chunk_size;
			c_n->gzfd = NULL;
		}

		rv->fsize += chunk_size;

		if (fd < 0) {
			/* Just calculating size, close the fd */
			close(chunk_fd);
			free(c_n);
		} else {
			if (c) {
				c->next = c_n;
			} else {
				rv->chunks = c_n;
			}
			c = c_n;
		}
	}
	fclose(fp);	
	return rv;
}


static void close_concat_file(struct concat_file * cf)
{
	struct chunk * c;

	if (!cf) {
		return;
	}

	for (c = cf->chunks; c;) {
		struct chunk * t;

		if (c->is_gzip && c->gzfd) {
			gzclose(c->gzfd);
		}
		close(c->fd);
		pthread_mutex_destroy(&c->lock);

		t = c;

		c = c->next;

		free(t);
	}

	close(cf->fd);

	free(cf);
}

static off_t get_concat_file_size(const char * path)
{
	struct concat_file * c = open_concat_file(-1, path);
	off_t rv;

	if (!c) {
		return 0;
	}

	rv = c->fsize;

	close_concat_file(c);

	return rv;
}

/* Read from a chunk at the given offset within the chunk.
   For gzip chunks, handles sequential access and position tracking.
   Thread-safe: uses per-chunk mutex to protect gzip state. */
static ssize_t read_chunk(struct chunk *c, void *buf, size_t count, off_t offset)
{
	ssize_t result;

	pthread_mutex_lock(&c->lock);

	if (!c->is_gzip) {
		/* Regular file: use pread for random access */
		result = pread(c->fd, buf, count, offset);
		pthread_mutex_unlock(&c->lock);
		return result;
	}

	/* Gzip file: sequential access only */
	if (offset < c->gz_pos) {
		/* Need to seek backward - must rewind and skip forward */
		gzrewind(c->gzfd);
		c->gz_pos = 0;
	}

	/* Skip forward to desired offset if needed */
	if (offset > c->gz_pos) {
		char skip_buf[4096];
		off_t to_skip = offset - c->gz_pos;

		while (to_skip > 0) {
			size_t skip_count = (to_skip > sizeof(skip_buf)) ? sizeof(skip_buf) : to_skip;
			int rv = gzread(c->gzfd, skip_buf, skip_count);
			if (rv <= 0) {
				pthread_mutex_unlock(&c->lock);
				return rv < 0 ? -EIO : 0;
			}
			c->gz_pos += rv;
			to_skip -= rv;
		}
	}

	/* Now read the actual data */
	int rv = gzread(c->gzfd, buf, count);
	if (rv > 0) {
		c->gz_pos += rv;
	}
	result = rv < 0 ? -EIO : rv;

	pthread_mutex_unlock(&c->lock);
	return result;
}

static int read_concat_file(int fd, void *buf, size_t count, off_t offset)
{
	struct concat_file * cf = open_files_find(fd);
	struct chunk * c;
	ssize_t bytes_read = 0;

	if (!cf) {
		return -EINVAL;
	}

	if (offset > cf->fsize) {
		return 0;
	}

	c = cf->chunks;

	/* Skip chunks until we find the one containing our offset */
	for (; c && offset >= c->fsize; c = c->next) {
		offset -= c->fsize;
	}

	/* Read across multiple chunks if needed */
	while (c && count > 0) {
		size_t to_read = count;
		ssize_t rv;

		if (to_read > c->fsize - offset) {
			to_read = c->fsize - offset;
		}

		rv = read_chunk(c, buf, to_read, offset);

		if (rv > 0) {
			buf += rv;
			bytes_read += rv;
			count -= rv;
			offset = 0;
			if (rv < to_read) {
				/* Short read, return what we have */
				return bytes_read;
			}
			c = c->next;
		} else if (rv == 0) {
			/* EOF */
			return bytes_read;
		} else {
			/* Error */
			return rv;
		}
	}

	return bytes_read;
}

static int is_concatfs_file(const char * path)
{
	char fpath[PATH_MAX];

	strncpy(fpath, path, sizeof(fpath));

	return (strstr(basename(fpath), "-concat-") != 0);
}

static int concatfs_readlink(const char *path, char *link, size_t size)
{
	int rv = 0;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;
    
	rv = readlink(fpath, link, size - 1);
	if (rv < 0) {
		rv = -errno;
	} else {
		link[rv] = '\0';
		rv = 0;
	}
	
	return rv;
}
static int concatfs_getattr(const char *path, struct stat *stbuf)
{
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	memset(stbuf, 0, sizeof(struct stat));

	if (lstat(fpath, stbuf) != 0)
		return -errno;
	
	if (is_concatfs_file(path)) {
		stbuf->st_size = get_concat_file_size(fpath);
	} 

	return 0;
}

static int concatfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			    off_t offset, struct fuse_file_info *fi)
{
	int retstat = 0;
	DIR *dp;
	struct dirent *de;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	dp = opendir(fpath);

	if (!dp) {
		return -errno;
	}

	de = readdir(dp);
	if (de == 0) {
		closedir(dp);
		return -errno;
	}
	
	do {
		if (filler(buf, de->d_name, NULL, 0) != 0) {
			closedir(dp);
			return -ENOMEM;
		}
	} while ((de = readdir(dp)) != NULL);
	
	closedir(dp);

	return retstat;
}

static int concatfs_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	fd = open(fpath, fi->flags);

	if (fd < 0) {
		return -errno;
	}

	fi->fh = fd;

	if (is_concatfs_file(path)) {
		open_files_push_front(open_concat_file(fd, fpath));
	}

	return 0;
}

static int concatfs_release(const char * path, struct fuse_file_info * fi)
{
	if (is_concatfs_file(path)) {
		close_concat_file(open_files_erase(fi->fh));
	} else {
		close(fi->fh);
	}

	return 0;
}

static int concatfs_read(const char *path, char *buf, size_t size, off_t offset,
			 struct fuse_file_info *fi)
{
	int rv = 0;

	if (is_concatfs_file(path)) {
		return read_concat_file(fi->fh, buf, size, offset);
	} else {
		rv = pread(fi->fh, buf, size, offset);
		if (rv < 0) {
			return -errno;
		}
	}

	return rv;
}

static int concatfs_write(
	const char *path, const char *buf, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	int rv = 0;

	if (is_concatfs_file(path)) {
		return -EINVAL;
	} else {
		rv = pwrite(fi->fh, buf, size, offset);
		if (rv < 0) {
			return -errno;
		}
	}

	return rv;
}

static int concatfs_mknod(const char *path, mode_t mode, dev_t dev)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = mknod(fpath, mode, dev);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_mkdir(const char *path, mode_t mode)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = mkdir(fpath, mode);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_unlink(const char *path)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = unlink(fpath);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_rmdir(const char *path)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = rmdir(fpath);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_symlink(const char *path, const char * link)
{
	int rv;
	char flink[PATH_MAX];

	if (make_path(flink, sizeof(flink), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = symlink(path, flink);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_rename(const char *path, const char *topath)
{
	int rv;
	char fpath[PATH_MAX];
	char ftopath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;
	if (make_path(ftopath, sizeof(ftopath), src_dir, topath) != 0)
		return -ENAMETOOLONG;
	
	rv = rename(fpath, ftopath);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_link(const char *path, const char *topath)
{
	int rv;
	char fpath[PATH_MAX];
	char ftopath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;
	if (make_path(ftopath, sizeof(ftopath), src_dir, topath) != 0)
		return -ENAMETOOLONG;
	
	rv = link(fpath, ftopath);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_chmod(const char *path, mode_t mode)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = chmod(fpath, mode);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = chown(fpath, uid, gid);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_truncate(const char *path, off_t nsize)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = truncate(fpath, nsize);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_utime(const char *path, struct utimbuf * buf)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;

	rv = utime(fpath, buf);
	if (rv < 0) {
		return -errno;
	}
	return rv;
}

static int concatfs_access(const char *path, int mask)
{
	int rv;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;
    
	rv = access(fpath, mask);
    
	if (rv < 0) {
		return -errno;
	}
    
	return rv;
}

static int concatfs_create(
	const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd = 0;
	char fpath[PATH_MAX];

	if (make_path(fpath, sizeof(fpath), src_dir, path) != 0)
		return -ENAMETOOLONG;
    
	fd = creat(fpath, mode);
    
	if (fd < 0) {
		return -errno;
	}

	fi->fh = fd;
    
	return 0;
}


static struct fuse_operations concatfs_oper = {
	.getattr	= concatfs_getattr,
	.readlink       = concatfs_readlink,
	.mknod          = concatfs_mknod,
	.mkdir          = concatfs_mkdir,
	.unlink         = concatfs_unlink,
	.rmdir          = concatfs_rmdir,
	.symlink        = concatfs_symlink,
	.rename         = concatfs_rename,
	.link           = concatfs_link,
	.chmod          = concatfs_chmod,
	.chown          = concatfs_chown,
	.truncate       = concatfs_truncate,
	.utime          = concatfs_utime,
	.open		= concatfs_open,
	.read		= concatfs_read,
	.write          = concatfs_write,
	.release        = concatfs_release,
	.readdir	= concatfs_readdir,
	.access         = concatfs_access,
	.create         = concatfs_create,
};

static void usage()
{
	fprintf(stderr, "Usage: poc_concatfs src-dir fuse-mount-options...\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		usage();
	}

	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr, 
			"WARNING! concatfs does *no* file access checking "
			"right now and therefore is *dangerous* to use "
			"as root!");
	}

	if (argv[1][0] == '/') {
		strncpy(src_dir, argv[1], sizeof(src_dir));
		src_dir[sizeof(src_dir) - 1] = '\0';
	} else {
		char cwd[PATH_MAX];

		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			fprintf(stderr, "Failed to get current directory\n");
			exit(-1);
		}

		if (make_path(src_dir, sizeof(src_dir), cwd, argv[1]) != 0) {
			fprintf(stderr, "Source path too long\n");
			exit(-1);
		}
	}

	pthread_mutex_init(&the_lock, NULL);

	char ** argv_ = (char**) calloc(argc, sizeof(char*));

	argv_[0] = argv[0];

	memcpy(argv_ + 1, argv + 2, (argc - 2) * sizeof(char*));

	return fuse_main(argc - 1, argv_, &concatfs_oper, NULL);
}

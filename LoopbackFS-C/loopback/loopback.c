/*
 FUSE: Filesystem in Userspace
 Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

 This program can be distributed under the terms of the GNU GPL.
 See the file LICENSE.txt.

 */

/*
 * Loopback macFUSE file system in C. Uses the high-level FUSE API.
 * Based on the fusexmp_fh.c example from the Linux FUSE distribution.
 * Amit Singh <http://osxbook.com>
 */

#include <AvailabilityMacros.h>

#define HAVE_EXCHANGE 0
#define HAVE_RENAMEX 1
#define HAVE_ACCESS 0

#define FUSE_USE_VERSION 26

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/sysctl.h>

struct path {
    bool fail;
    char value[PATH_MAX];
};

#if defined(_POSIX_C_SOURCE)
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;
#endif

struct loopback {
    uint32_t blocksize;
    bool case_insensitive;
    char mount_point[PATH_MAX];        // Store the mount point path
    size_t mount_point_len;            // Length of mount point path
    char backup_path[PATH_MAX];        // Backup location (mount_point + ".fuse")
    bool backup_created;               // Whether we created the backup
};

static struct loopback loopback;

// Function to move all contents from src_dir to dst_dir
static int move_directory_contents(const char *src_dir, const char *dst_dir) {
    DIR *dir = opendir(src_dir);
    if (!dir) {
        fprintf(stderr, "Failed to open source directory %s: %s\n", src_dir, strerror(errno));
        return -1;
    }

    struct dirent *entry;
    int failed = 0;

    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char src_path[PATH_MAX], dst_path[PATH_MAX];
        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, entry->d_name);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, entry->d_name);

        if (rename(src_path, dst_path) != 0) {
            fprintf(stderr, "Failed to move %s to %s: %s\n", src_path, dst_path, strerror(errno));
            failed = 1;
            // Continue trying to move other files
        }
    }

    closedir(dir);
    return failed ? -1 : 0;
}

// Function to create backup of mount point
static int create_mount_point_backup(void) {
    if (loopback.mount_point_len == 0) {
        return 0; // No mount point to backup
    }

    // For macOS: assume /foo maps to /System/Volumes/Data/foo
    char real_mount_path[PATH_MAX];
    char real_backup_path[PATH_MAX];

    snprintf(real_mount_path, sizeof(real_mount_path), "/System/Volumes/Data%s", loopback.mount_point);
    snprintf(real_backup_path, sizeof(real_backup_path), "/System/Volumes/Data%s.fuse", loopback.mount_point);
    snprintf(loopback.backup_path, sizeof(loopback.backup_path), "%s", real_backup_path);

    // Check if backup already exists from previous run
    struct stat backup_st;
    if (stat(real_backup_path, &backup_st) == 0) {
        fprintf(stderr, "Using existing backup: %s\n", real_backup_path);
        loopback.backup_created = true;
        return 0;
    }

    // Check if mount point exists to backup
    struct stat mount_st;
    if (stat(real_mount_path, &mount_st) != 0) {
        fprintf(stderr, "Mount point %s does not exist, no backup needed\n", real_mount_path);
        return 0;
    }

    // Create backup directory
    if (mkdir(real_backup_path, 0755) != 0) {
        fprintf(stderr, "Failed to create backup directory %s: %s\n", real_backup_path, strerror(errno));
        return -1;
    }

    // Move contents from mount_point to backup_path
    if (move_directory_contents(real_mount_path, real_backup_path) == 0) {
        fprintf(stderr, "Created backup by moving contents: %s/* -> %s/\n", real_mount_path, real_backup_path);
        loopback.backup_created = true;
        return 0;
    } else {
        fprintf(stderr, "Failed to move contents for backup\n");
        rmdir(real_backup_path); // Clean up empty backup directory
        return -1;
    }
}

// Function to restore mount point from backup
static void restore_mount_point_backup(void) {
    if (!loopback.backup_created) {
        return; // No backup to restore
    }

    // For macOS: construct real paths
    char real_mount_path[PATH_MAX];
    snprintf(real_mount_path, sizeof(real_mount_path), "/System/Volumes/Data%s", loopback.mount_point);

    // Remove the empty mount point directory left by FUSE (if it exists)
    rmdir(loopback.mount_point);

    // Move contents back from backup to mount point
    if (move_directory_contents(loopback.backup_path, real_mount_path) == 0) {
        fprintf(stderr, "Restored backup by moving contents: %s/* -> %s/\n", loopback.backup_path, real_mount_path);

        // Remove the now-empty backup directory
        if (rmdir(loopback.backup_path) == 0) {
            fprintf(stderr, "Removed backup directory: %s\n", loopback.backup_path);
        } else {
            fprintf(stderr, "Warning: Failed to remove backup directory: %s\n", loopback.backup_path);
        }
    } else {
        fprintf(stderr, "Failed to restore backup contents\n");
    }
    loopback.backup_created = false;
}

// Function to get parent PID of a given PID
static pid_t get_parent_pid(pid_t pid) {
    struct proc_bsdinfo proc_info;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc_info, sizeof(proc_info)) <= 0) {
        return -1; // Process doesn't exist or error
    }
    return proc_info.pbi_ppid;
}

// Function to get WRAPPER value from process environment variables
static bool get_wrapper_from_env_process(pid_t pid, char* result_buffer, size_t buffer_size) {

    // Get the full process args and environment data
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t size = 0;

    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0) {
        fprintf(stderr, "    sysctl size query failed for PID %d (errno=%d)\n", pid, errno);
        return false;
    }

    // Sanity check the size
    if (size < sizeof(int) || size > 1024 * 1024) { // Max 1MB seems reasonable
        fprintf(stderr, "    suspicious size %zu for PID %d, aborting\n", size, pid);
        return false;
    }

    char *proc_data = malloc(size);
    if (!proc_data) {
        fprintf(stderr, "    malloc failed for PID %d\n", pid);
        return false;
    }

    if (sysctl(mib, 3, proc_data, &size, NULL, 0) != 0) {
        fprintf(stderr, "    sysctl data query failed for PID %d (errno=%d)\n", pid, errno);
        free(proc_data);
        return false;
    }

    // Bounds checking - ensure we have at least space for argc
    if (size < sizeof(int)) {
        fprintf(stderr, "    insufficient data for PID %d (size=%zu)\n", pid, size);
        free(proc_data);
        return false;
    }

    // Format: argc, then executable path, then args, then env
    int argc = *(int*)proc_data;
    char *ptr = proc_data + sizeof(int);
    char *data_end = proc_data + size;

    // Sanity check argc
    if (argc < 0 || argc > 1000) { // Reasonable limit
        fprintf(stderr, "    suspicious argc %d for PID %d, aborting\n", argc, pid);
        free(proc_data);
        return false;
    }

    fprintf(stderr, "    PID %d has %d args, checking environment...\n", pid, argc);

    // Skip over the executable path with bounds checking
    if (ptr >= data_end) {
        fprintf(stderr, "    no space for executable path in PID %d\n", pid);
        free(proc_data);
        return false;
    }

    size_t exec_len = strnlen(ptr, data_end - ptr);
    if (exec_len == (size_t)(data_end - ptr)) {
        fprintf(stderr, "    unterminated executable path in PID %d\n", pid);
        free(proc_data);
        return false;
    }
    ptr += exec_len + 1;

    // Skip any null padding after executable path
    while (ptr < data_end && *ptr == '\0') {
        ptr++;
    }

    // Skip over all the arguments with bounds checking
    for (int i = 0; i < argc && ptr < data_end; i++) {
        if (*ptr != '\0') {
            size_t arg_len = strnlen(ptr, data_end - ptr);
            if (arg_len == (size_t)(data_end - ptr)) {
                fprintf(stderr, "    unterminated arg[%d] in PID %d\n", i, pid);
                free(proc_data);
                return false;
            }
            fprintf(stderr, "    arg[%d]: %.*s\n", i, (int)arg_len, ptr);
            ptr += arg_len + 1;
        } else {
            ptr++;
        }
    }

    // Now we're at the environment variables
    int env_count = 0;
    // Look through environment variables for WRAPPER=value with bounds checking
    while (ptr < data_end && *ptr != '\0') {
        size_t env_len = strnlen(ptr, data_end - ptr);
        if (env_len == (size_t)(data_end - ptr)) {
            fprintf(stderr, "    unterminated env var #%d in PID %d\n", env_count + 1, pid);
            break;
        }

        env_count++;
        if (env_len >= 8 && strncmp(ptr, "WRAPPER=", 8) == 0) {
            // Found WRAPPER= environment variable, extract the value
            size_t value_len = env_len - 8;
            if (value_len >= buffer_size) {
                value_len = buffer_size - 1;
            }
            strncpy(result_buffer, ptr + 8, value_len);
            result_buffer[value_len] = '\0';
            fprintf(stderr, "    Found WRAPPER=%s (env var #%d)\n", result_buffer, env_count);
            free(proc_data);
            return true;
        }
        ptr += env_len + 1;
    }

    fprintf(stderr, "    Checked %d environment variables, no WRAPPER found\n", env_count);
    free(proc_data);
    return false;
}

// Function to build redirected path based on wrapper value
static void build_redirected_path(const char* original_path, const char* wrapper_value, char* result_buf, size_t buf_size) {
    // Special case: if original_path is just "/", return the wrapper_value directory
    if (strcmp(original_path, "/") == 0) {
        strncpy(result_buf, wrapper_value, buf_size - 1);
        result_buf[buf_size - 1] = '\0';
        return;
    }

    // If wrapper_value ends with '/', remove it to avoid double slashes
    size_t wrapper_len = strlen(wrapper_value);
    if (wrapper_len > 0 && wrapper_value[wrapper_len - 1] == '/') {
        snprintf(result_buf, buf_size, "%.*s%s",
                (int)(wrapper_len - 1), wrapper_value, original_path);
    } else {
        snprintf(result_buf, buf_size, "%s%s",
                wrapper_value, original_path);
    }
}

// Structure to hold wrapper detection results
struct wrapper_info {
    int found;
    pid_t pid;
    char value[256];
};

// Forward declaration
static struct wrapper_info find_wrapper_in_tree(pid_t starting_pid);

// Helper function to apply wrapper detection and path redirection
static struct path apply_wrapper_redirect_with_context(const char* original_path, const char* operation_name, struct fuse_context *context) {
    struct path result = { .fail = false };

    if (context) {
        // Check if this is fseventsd - return early to avoid conflicts
        char proc_name[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(context->pid, proc_name, sizeof(proc_name)) > 0) {
            char *basename = strrchr(proc_name, '/');
            basename = basename ? basename + 1 : proc_name;

            if (strcmp(basename, "fseventsd") == 0) {
                fprintf(stderr, "*** %s BLOCKING fseventsd PID %d ***\n", operation_name, context->pid);
                result.fail = true;
                return result;
            }
        }

        struct wrapper_info wrapper = find_wrapper_in_tree(context->pid);
        if (wrapper.found && strlen(wrapper.value) > 0) {
            // Wrapper detected - redirect to wrapper path
            build_redirected_path(original_path, wrapper.value, result.value, sizeof(result.value));
            fprintf(stderr, "*** %s REDIRECT: %s -> %s ***\n", operation_name, original_path, result.value);
            return result;
        }
    }

    // No wrapper - pass through to backup location (original content)
    if (loopback.backup_created) {
        build_redirected_path(original_path, loopback.backup_path, result.value, sizeof(result.value));
        fprintf(stderr, "*** %s PASSTHROUGH: %s -> %s ***\n", operation_name, original_path, result.value);
        return result;
    }

    strncpy(result.value, original_path, sizeof(result.value) - 1);
    result.value[sizeof(result.value) - 1] = '\0';
    return result;
}

// Function to find WRAPPER environment variable in process tree
static struct wrapper_info find_wrapper_in_tree(pid_t starting_pid) {
    struct wrapper_info result = { .found = 0, .pid = -1, .value = "" };
    pid_t current_pid = starting_pid;
    int depth = 0;

    fprintf(stderr, "Searching for WRAPPER in process tree starting from PID %d:\n", starting_pid);

    while (current_pid > 1 && depth < 10) {
        // Check if this process has WRAPPER in its environment variables
        char wrapper_value[256];
        bool found_wrapper = get_wrapper_from_env_process(current_pid, wrapper_value, sizeof(wrapper_value));

        fprintf(stderr, "  PID %d: %s\n",
                current_pid,
                found_wrapper ? "HAS WRAPPER!" : "no wrapper");

        if (found_wrapper) {
            result.found = 1;
            result.pid = current_pid;
            strncpy(result.value, wrapper_value, sizeof(result.value) - 1);
            result.value[sizeof(result.value) - 1] = '\0';
            fprintf(stderr, "Found WRAPPER=%s at PID %d!\n", wrapper_value, current_pid);
            return result;
        }

        // Get parent PID
        pid_t parent_pid = get_parent_pid(current_pid);
        if (parent_pid <= 0) {
            break;
        }

        current_pid = parent_pid;
        depth++;
    }

    fprintf(stderr, "No WRAPPER found in process tree\n");
    return result;
}

// Function to print process tree for debugging
static void print_process_tree(pid_t starting_pid) {
    pid_t current_pid = starting_pid;
    char proc_name[PROC_PIDPATHINFO_MAXSIZE];

    fprintf(stderr, "Process tree for PID %d:\n", starting_pid);

    int depth = 0;
    while (current_pid > 1 && depth < 10) { // Limit depth to avoid infinite loops
        // Get process name
        if (proc_pidpath(current_pid, proc_name, sizeof(proc_name)) > 0) {
            // Extract just the executable name from full path
            char *basename = strrchr(proc_name, '/');
            if (basename) {
                basename++;
            } else {
                basename = proc_name;
            }

            // Print with indentation
            for (int i = 0; i < depth; i++) fprintf(stderr, "  ");
            fprintf(stderr, "PID %d: %s\n", current_pid, basename);
        } else {
            for (int i = 0; i < depth; i++) fprintf(stderr, "  ");
            fprintf(stderr, "PID %d: <unknown>\n", current_pid);
        }

        // Get parent PID
        pid_t parent_pid = get_parent_pid(current_pid);
        if (parent_pid <= 0) {
            break;
        }

        current_pid = parent_pid;
        depth++;
    }
    fprintf(stderr, "\n");
}

static int
loopback_getattr(const char *path, struct stat *stbuf)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "GETATTR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = lstat(redirected.value, stbuf);

    /*
     * The optimal I/O size can be set on a per-file basis. Setting st_blksize
     * to zero will cause the kernel extension to fall back on the global I/O
     * size which can be specified at mount-time (option iosize).
     */
    stbuf->st_blksize = 0;

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_fgetattr(const char *path, struct stat *stbuf,
                  struct fuse_file_info *fi)
{
    int res;

    (void)path;

    res = fstat(fi->fh, stbuf);

    // Fall back to global I/O size. See loopback_getattr().
    stbuf->st_blksize = 0;

    if (res == -1) {
        return -errno;
    }

    return 0;
}

#if HAVE_ACCESS

static int
loopback_access(const char *path, int mask)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "ACCESS", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    /*
     * Standard access permission flags:
     * F_OK            test for existence of file
     * X_OK            test for execute or search permission
     * W_OK            test for write permission
     * R_OK            test for read permission
     *
     * Extended access permission flags that can be enabled by setting
     * FUSE_CAP_ACCESS_EXTENDED (See loopback_init()):
     * _READ_OK        read file data / read directory
     * _WRITE_OK       write file data / add file to directory
     * _EXECUTE_OK     execute file / search in directory
     * _DELETE_OK      delete file / delete directory
     * _APPEND_OK      append to file / add subdirectory to directory
     * _RMFILE_OK      remove file from directory
     * _RATTR_OK       read basic attributes
     * _WATTR_OK       write basic attributes
     * _REXT_OK        read extended attributes
     * _WEXT_OK        write extended attributes
     * _RPERM_OK       read permissions
     * _WPERM_OK       write permissions
     * _CHOWN_OK       change ownership
     */

    res = access(redirected.value, mask & (F_OK | X_OK | W_OK | R_OK));
    if (res == -1)
        return -errno;

    return 0;
}

#endif /* HAVE_ACCESS */

static int
loopback_readlink(const char *path, char *buf, size_t size)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "READLINK", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = readlink(redirected.value, buf, size - 1);
    if (res == -1) {
        return -errno;
    }

    buf[res] = '\0';

    return 0;
}

struct loopback_dirp {
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

static int
loopback_opendir(const char *path, struct fuse_file_info *fi)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "OPENDIR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    struct loopback_dirp *d = malloc(sizeof(struct loopback_dirp));
    if (d == NULL) {
        return -ENOMEM;
    }

    d->dp = opendir(redirected.value);
    if (d->dp == NULL) {
        res = -errno;
        free(d);
        return res;
    }

    d->offset = 0;
    d->entry = NULL;

    fi->fh = (unsigned long)d;

    return 0;
}

static inline struct loopback_dirp *
get_dirp(struct fuse_file_info *fi)
{
    return (struct loopback_dirp *)(uintptr_t)fi->fh;
}

static int
loopback_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi)
{
    struct loopback_dirp *d = get_dirp(fi);

    (void)path;

    if (offset == 0) {
        rewinddir(d->dp);
        d->entry = NULL;
        d->offset = 0;
    } else if (offset != d->offset) {
        // Subtract the one that we add when calling telldir() below
        seekdir(d->dp, offset - 1);
        d->entry = NULL;
        d->offset = offset;
    }

    while (1) {
        struct stat st;
        off_t nextoff;

        if (!d->entry) {
            d->entry = readdir(d->dp);
            if (!d->entry) {
                break;
            }
        }

        memset(&st, 0, sizeof(st));
        st.st_ino = d->entry->d_ino;
        st.st_mode = d->entry->d_type << 12;

        /*
         * Under macOS, telldir() may return 0 the first time it is called.
         * But for libfuse, an offset of zero means that offsets are not
         * supported, so we shift everything by one.
         */
        nextoff = telldir(d->dp) + 1;

        if (filler(buf, d->entry->d_name, &st, nextoff)) {
            break;
        }

        d->entry = NULL;
        d->offset = nextoff;
    }

    return 0;
}

static int
loopback_releasedir(const char *path, struct fuse_file_info *fi)
{
    struct loopback_dirp *d = get_dirp(fi);

    (void)path;

    closedir(d->dp);
    free(d);

    return 0;
}

static int
loopback_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "MKNOD", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    if (S_ISFIFO(mode)) {
        res = mkfifo(redirected.value, mode);
    } else {
        res = mknod(redirected.value, mode, rdev);
    }

    if (res == -1) {
        return -errno;
    }

    // Set proper ownership to the calling user
    if (context && chown(redirected.value, context->uid, context->gid) == -1) {
        fprintf(stderr, "Warning: Failed to set ownership for %s: %s\n", redirected.value, strerror(errno));
    }

    return 0;
}

static int
loopback_mkdir(const char *path, mode_t mode)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "MKDIR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = mkdir(redirected.value, mode);
    if (res == -1) {
        return -errno;
    }

    // Set proper ownership to the calling user
    if (context && chown(redirected.value, context->uid, context->gid) == -1) {
        fprintf(stderr, "Warning: Failed to set ownership for %s: %s\n", redirected.value, strerror(errno));
    }

    return 0;
}

static int
loopback_unlink(const char *path)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "UNLINK", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = unlink(redirected.value);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_rmdir(const char *path)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "RMDIR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = rmdir(redirected.value);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_symlink(const char *from, const char *to)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(to, "SYMLINK", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = symlink(from, redirected.value);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_rename(const char *from, const char *to)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected_from = apply_wrapper_redirect_with_context(from, "RENAME1", context);
    struct path redirected_to = apply_wrapper_redirect_with_context(to, "RENAME2", context);

    if (redirected_from.fail || redirected_to.fail) {
        return -ENOTSUP;
    }

    res = rename(redirected_from.value, redirected_to.value);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

#if HAVE_EXCHANGE

static int
loopback_exchange(const char *path1, const char *path2, unsigned long options)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected1 = apply_wrapper_redirect_with_context(path1, "EXCHANGE1", context);
    struct path redirected2 = apply_wrapper_redirect_with_context(path2, "EXCHANGE2", context);

    if (redirected1.fail || redirected2.fail) {
        return -ENOTSUP;
    }

    res = exchangedata(redirected1.value, redirected2.value, options);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

#endif /* HAVE_EXCHANGE */

static int
loopback_link(const char *from, const char *to)
{
    int res;

    res = link(from, to);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_fsetattr_x(const char *path, struct setattr_x *attr,
                    struct fuse_file_info *fi)
{
    int res;
    uid_t uid = -1;
    gid_t gid = -1;

    if (SETATTR_WANTS_MODE(attr)) {
        res = fchmod(fi->fh, attr->mode);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_UID(attr)) {
        uid = attr->uid;
    }

    if (SETATTR_WANTS_GID(attr)) {
        gid = attr->gid;
    }

    if ((uid != -1) || (gid != -1)) {
        res = fchown(fi->fh, uid, gid);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_SIZE(attr)) {
        res = ftruncate(fi->fh, attr->size);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_MODTIME(attr)) {
        struct timeval tv[2];
        if (!SETATTR_WANTS_ACCTIME(attr)) {
            gettimeofday(&tv[0], NULL);
        } else {
            tv[0].tv_sec = attr->acctime.tv_sec;
            tv[0].tv_usec = attr->acctime.tv_nsec / 1000;
        }
        tv[1].tv_sec = attr->modtime.tv_sec;
        tv[1].tv_usec = attr->modtime.tv_nsec / 1000;
        res = futimes(fi->fh, tv);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_CRTIME(attr)) {
        struct attrlist attributes;

        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.reserved = 0;
        attributes.commonattr = ATTR_CMN_CRTIME;
        attributes.dirattr = 0;
        attributes.fileattr = 0;
        attributes.forkattr = 0;
        attributes.volattr = 0;

        res = fsetattrlist(fi->fh, &attributes, &attr->crtime,
                           sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_CHGTIME(attr)) {
        struct attrlist attributes;

        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.reserved = 0;
        attributes.commonattr = ATTR_CMN_CHGTIME;
        attributes.dirattr = 0;
        attributes.fileattr = 0;
        attributes.forkattr = 0;
        attributes.volattr = 0;

        res = fsetattrlist(fi->fh, &attributes, &attr->chgtime,
                           sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_BKUPTIME(attr)) {
        struct attrlist attributes;

        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.reserved = 0;
        attributes.commonattr = ATTR_CMN_BKUPTIME;
        attributes.dirattr = 0;
        attributes.fileattr = 0;
        attributes.forkattr = 0;
        attributes.volattr = 0;

        res = fsetattrlist(fi->fh, &attributes, &attr->bkuptime,
                           sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_FLAGS(attr)) {
        res = fchflags(fi->fh, attr->flags);
        if (res == -1) {
            return -errno;
        }
    }

    return 0;
}

static int
loopback_setattr_x(const char *path, struct setattr_x *attr)
{
    int res;
    uid_t uid = -1;
    gid_t gid = -1;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "SETATTR_X", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    if (SETATTR_WANTS_MODE(attr)) {
        res = lchmod(redirected.value, attr->mode);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_UID(attr)) {
        uid = attr->uid;
    }

    if (SETATTR_WANTS_GID(attr)) {
        gid = attr->gid;
    }

    if ((uid != -1) || (gid != -1)) {
        res = lchown(redirected.value, uid, gid);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_SIZE(attr)) {
        res = truncate(redirected.value, attr->size);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_MODTIME(attr)) {
        struct timeval tv[2];
        if (!SETATTR_WANTS_ACCTIME(attr)) {
            gettimeofday(&tv[0], NULL);
        } else {
            tv[0].tv_sec = attr->acctime.tv_sec;
            tv[0].tv_usec = attr->acctime.tv_nsec / 1000;
        }
        tv[1].tv_sec = attr->modtime.tv_sec;
        tv[1].tv_usec = attr->modtime.tv_nsec / 1000;
        res = lutimes(redirected.value, tv);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_CRTIME(attr)) {
        struct attrlist attributes;

        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.reserved = 0;
        attributes.commonattr = ATTR_CMN_CRTIME;
        attributes.dirattr = 0;
        attributes.fileattr = 0;
        attributes.forkattr = 0;
        attributes.volattr = 0;

        res = setattrlist(redirected.value, &attributes, &attr->crtime,
                          sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_CHGTIME(attr)) {
        struct attrlist attributes;

        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.reserved = 0;
        attributes.commonattr = ATTR_CMN_CHGTIME;
        attributes.dirattr = 0;
        attributes.fileattr = 0;
        attributes.forkattr = 0;
        attributes.volattr = 0;

        res = setattrlist(redirected.value, &attributes, &attr->chgtime,
                          sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_BKUPTIME(attr)) {
        struct attrlist attributes;

        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.reserved = 0;
        attributes.commonattr = ATTR_CMN_BKUPTIME;
        attributes.dirattr = 0;
        attributes.fileattr = 0;
        attributes.forkattr = 0;
        attributes.volattr = 0;

        res = setattrlist(redirected.value, &attributes, &attr->bkuptime,
                          sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_FLAGS(attr)) {
        res = lchflags(redirected.value, attr->flags);
        if (res == -1) {
            return -errno;
        }
    }

    return 0;
}

static int
loopback_getxtimes(const char *path, struct timespec *bkuptime,
                   struct timespec *crtime)
{
    int res = 0;
    struct attrlist attributes;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "GETXTIMES", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
    attributes.reserved    = 0;
    attributes.commonattr  = 0;
    attributes.dirattr     = 0;
    attributes.fileattr    = 0;
    attributes.forkattr    = 0;
    attributes.volattr     = 0;

    struct xtimeattrbuf {
        uint32_t size;
        struct timespec xtime;
    } __attribute__ ((packed));

    struct xtimeattrbuf buf;

    attributes.commonattr = ATTR_CMN_BKUPTIME;
    res = getattrlist(redirected.value, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
    if (res == 0) {
        (void)memcpy(bkuptime, &(buf.xtime), sizeof(struct timespec));
    } else {
        (void)memset(bkuptime, 0, sizeof(struct timespec));
    }

    attributes.commonattr = ATTR_CMN_CRTIME;
    res = getattrlist(redirected.value, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
    if (res == 0) {
        (void)memcpy(crtime, &(buf.xtime), sizeof(struct timespec));
    } else {
        (void)memset(crtime, 0, sizeof(struct timespec));
    }

    return 0;
}

static int
loopback_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "CREATE", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    fd = open(redirected.value, fi->flags, mode);
    if (fd == -1) {
        return -errno;
    }

    // Set proper ownership to the calling user
    if (context && fchown(fd, context->uid, context->gid) == -1) {
        fprintf(stderr, "Warning: Failed to set ownership for %s: %s\n", redirected.value, strerror(errno));
    }

    fi->fh = fd;
    return 0;
}

static int
loopback_open(const char *path, struct fuse_file_info *fi)
{
    int fd;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "OPEN", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    fd = open(redirected.value, fi->flags);
    if (fd == -1) {
        return -errno;
    }

    fi->fh = fd;
    return 0;
}

static int
loopback_read(const char *path, char *buf, size_t size, off_t offset,
              struct fuse_file_info *fi)
{
    int res;

    (void)path;
    res = pread(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }

    return res;
}

static int
loopback_write(const char *path, const char *buf, size_t size,
               off_t offset, struct fuse_file_info *fi)
{
    int res;

    (void)path;

    res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }

    return res;
}

static int
loopback_flush(const char *path, struct fuse_file_info *fi)
{
    int res;

    (void)path;

    res = close(dup(fi->fh));
    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;

    close(fi->fh);

    return 0;
}

static int
loopback_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    int res;

    (void)path;

    (void)isdatasync;

    res = fsync(fi->fh);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_setxattr(const char *path, const char *name, const char *value,
                  size_t size, int flags, uint32_t position)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "SETXATTR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    flags |= XATTR_NOFOLLOW;
    if (strncmp(name, "com.apple.", 10) == 0) {
        char new_name[MAXPATHLEN] = "org.apple.";
        strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);

        res = setxattr(redirected.value, new_name, value, size, position, flags);
    } else {
        res = setxattr(redirected.value, name, value, size, position, flags);
    }

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_getxattr(const char *path, const char *name, char *value, size_t size,
                  uint32_t position)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "GETXATTR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    if (strncmp(name, "com.apple.", 10) == 0) {
        char new_name[MAXPATHLEN] = "org.apple.";
        strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);

        res = getxattr(redirected.value, new_name, value, size, position, XATTR_NOFOLLOW);
    } else {
        res = getxattr(redirected.value, name, value, size, position, XATTR_NOFOLLOW);
    }

    if (res == -1) {
        return -errno;
    }

    return res;
}

static int
loopback_listxattr(const char *path, char *list, size_t size)
{
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "LISTXATTR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    ssize_t res = listxattr(redirected.value, list, size, XATTR_NOFOLLOW);
    if (res > 0) {
        if (list) {
            size_t len = 0;
            char *curr = list;
            do {
                size_t thislen = strlen(curr) + 1;
                if (strncmp(curr, "com.apple.", 10) == 0) {
                    curr[0] = 'o';
                    curr[1] = 'r';
                    curr[2] = 'g';
                }
                curr += thislen;
                len += thislen;
            } while (len < res);
        } else {
            /*
            ssize_t res2 = getxattr(redirected.value, G_KAUTH_FILESEC_XATTR, NULL, 0, 0,
                                    XATTR_NOFOLLOW);
            if (res2 >= 0) {
                res -= sizeof(G_KAUTH_FILESEC_XATTR);
            }
            */
        }
    }

    if (res == -1) {
        return -errno;
    }

    return res;
}

static int
loopback_removexattr(const char *path, const char *name)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "REMOVEXATTR", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    if (strncmp(name, "com.apple.", 10) == 0) {
        char new_name[MAXPATHLEN] = "org.apple.";
        strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);

        res = removexattr(redirected.value, new_name, XATTR_NOFOLLOW);
    } else {
        res = removexattr(redirected.value, name, XATTR_NOFOLLOW);
    }

    if (res == -1) {
        return -errno;
    }

    return 0;
}

static int
loopback_fallocate(const char *path, int mode, off_t offset, off_t length,
                   struct fuse_file_info *fi)
{
    fstore_t fstore;

    if (!(mode & PREALLOCATE)) {
        return -ENOTSUP;
    }

    fstore.fst_flags = 0;
    if (mode & ALLOCATECONTIG) {
        fstore.fst_flags |= F_ALLOCATECONTIG;
    }
    if (mode & ALLOCATEALL) {
        fstore.fst_flags |= F_ALLOCATEALL;
    }

    if (mode & ALLOCATEFROMPEOF) {
        fstore.fst_posmode = F_PEOFPOSMODE;
    } else if (mode & ALLOCATEFROMVOL) {
        fstore.fst_posmode = F_VOLPOSMODE;
    }

    fstore.fst_offset = offset;
    fstore.fst_length = length;

    if (fcntl(fi->fh, F_PREALLOCATE, &fstore) == -1) {
        return -errno;
    } else {
        return 0;
    }
}

static int
loopback_setvolname(const char *name)
{
    return 0;
}

static int
loopback_statfs_x(const char *path, struct statfs *stbuf)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected = apply_wrapper_redirect_with_context(path, "STATFS", context);

    if (redirected.fail) {
        return -ENOTSUP;
    }

    res = statfs(redirected.value, stbuf);
    if (res == -1) {
        return -errno;
    }

    stbuf->f_blocks = stbuf->f_blocks * stbuf->f_bsize / loopback.blocksize;
    stbuf->f_bavail = stbuf->f_bavail * stbuf->f_bsize / loopback.blocksize;
    stbuf->f_bfree = stbuf->f_bfree * stbuf->f_bsize / loopback.blocksize;
    stbuf->f_bsize = loopback.blocksize;

    return 0;
}

#if HAVE_RENAMEX

static int
loopback_renamex(const char *path1, const char *path2, unsigned int flags)
{
    int res;
    struct fuse_context *context = fuse_get_context();
    struct path redirected_path1 = apply_wrapper_redirect_with_context(path1, "RENAMEX1", context);
    struct path redirected_path2 = apply_wrapper_redirect_with_context(path2, "RENAMEX2", context);

    if (redirected_path1.fail || redirected_path2.fail) {
        return -ENOTSUP;
    }

    res = renamex_np(redirected_path1.value, redirected_path2.value, flags);
    if (res == -1) {
        return -errno;
    }

    return 0;
}

#endif /* HAVE_RENAMEX */

void *
loopback_init(struct fuse_conn_info *conn)
{
    conn->want |= FUSE_CAP_VOL_RENAME | FUSE_CAP_XTIMES | FUSE_CAP_NODE_RWLOCK;

#if HAVE_ACCESS
    conn->want |= FUSE_CAP_ACCESS_EXTENDED;
#endif

#ifdef FUSE_ENABLE_CASE_INSENSITIVE
    if (loopback.case_insensitive) {
        conn->want |= FUSE_CAP_CASE_INSENSITIVE;
    }
#endif

    return NULL;
}

void
loopback_destroy(void *userdata)
{
    /* nothing - backup restoration happens in main() after fuse_main() */
}

static struct fuse_operations loopback_oper = {
    .init        = loopback_init,
    .destroy     = loopback_destroy,
    .getattr     = loopback_getattr,
    .fgetattr    = loopback_fgetattr,
#if HAVE_ACCESS
    .access      = loopback_access,
#endif
    .readlink    = loopback_readlink,
    .opendir     = loopback_opendir,
    .readdir     = loopback_readdir,
    .releasedir  = loopback_releasedir,
    .mknod       = loopback_mknod,
    .mkdir       = loopback_mkdir,
    .symlink     = loopback_symlink,
    .unlink      = loopback_unlink,
    .rmdir       = loopback_rmdir,
    .rename      = loopback_rename,
    .link        = loopback_link,
    .create      = loopback_create,
    .open        = loopback_open,
    .read        = loopback_read,
    .write       = loopback_write,
    .flush       = loopback_flush,
    .release     = loopback_release,
    .fsync       = loopback_fsync,
    .setxattr    = loopback_setxattr,
    .getxattr    = loopback_getxattr,
    .listxattr   = loopback_listxattr,
    .removexattr = loopback_removexattr,
#if HAVE_EXCHANGE
    .exchange    = loopback_exchange,
#endif
    .getxtimes   = loopback_getxtimes,
    .setattr_x   = loopback_setattr_x,
    .fsetattr_x  = loopback_fsetattr_x,
    .fallocate   = loopback_fallocate,
    .setvolname  = loopback_setvolname,
    .statfs_x    = loopback_statfs_x,
#if HAVE_RENAMEX
    .renamex     = loopback_renamex,
#endif

    .flag_nullpath_ok = 1,
    .flag_nopath = 1,
};

static const struct fuse_opt loopback_opts[] = {
    { "fsblocksize=%u", offsetof(struct loopback, blocksize), 0 },
    { "case_insensitive", offsetof(struct loopback, case_insensitive), true },
    FUSE_OPT_END
};

int
main(int argc, char *argv[])
{
    int res = 0;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    loopback.blocksize = 4096;
    loopback.case_insensitive = 0;
    loopback.mount_point[0] = '\0';
    loopback.mount_point_len = 0;
    loopback.backup_path[0] = '\0';
    loopback.backup_created = false;

    if (fuse_opt_parse(&args, &loopback, loopback_opts, NULL) == -1) {
        exit(1);
    }

    // Find the mount point from command line arguments
    // Look for the first argument that looks like a path (starts with /)
    for (int i = 1; i < args.argc; i++) {
        if (args.argv[i][0] == '/') {
            strncpy(loopback.mount_point, args.argv[i], sizeof(loopback.mount_point) - 1);
            loopback.mount_point[sizeof(loopback.mount_point) - 1] = '\0';
            loopback.mount_point_len = strlen(loopback.mount_point);
            fprintf(stderr, "Mount point set to: %s (len=%zu)\n", loopback.mount_point, loopback.mount_point_len);
            break;
        }
    }

    // Create backup of mount point before starting FUSE
    if (create_mount_point_backup() != 0) {
        fprintf(stderr, "Failed to create backup, cannot proceed\n");
        fuse_opt_free_args(&args);
        return 1;
    }

    umask(0);
    res = fuse_main(args.argc, args.argv, &loopback_oper, NULL);

    // Restore backup after FUSE exits
    restore_mount_point_backup();

    fuse_opt_free_args(&args);
    return res;
}

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

// File location enumeration for overlay filesystem
typedef enum {
    OVERLAY_UPPER,      // File exists in upper layer
    OVERLAY_LOWER,      // File exists in lower layer
    OVERLAY_WHITEOUT,   // File is marked as deleted
    OVERLAY_NONE        // File doesn't exist anywhere
} overlay_location_t;

// Structure to hold overlay detection results
struct overlay_info {
    int found;
    pid_t pid;
    char upper_dir[256];
    char lower_dir[256];
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

// Function to get specific environment variable value from process
// Returns true if env variable found, false otherwise
// value_out must be at least value_size bytes
static bool get_env_from_process(pid_t pid, const char* env_name, char* value_out, size_t value_size) {

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
    size_t env_name_len = strlen(env_name);
    size_t search_len = env_name_len + 1; // +1 for the '=' sign

    // Look through environment variables for env_name=value with bounds checking
    while (ptr < data_end && *ptr != '\0') {
        size_t env_len = strnlen(ptr, data_end - ptr);
        if (env_len == (size_t)(data_end - ptr)) {
            fprintf(stderr, "    unterminated env var #%d in PID %d\n", env_count + 1, pid);
            break;
        }

        env_count++;
        if (env_len >= search_len && strncmp(ptr, env_name, env_name_len) == 0 && ptr[env_name_len] == '=') {
            // Found env_name= environment variable, extract the value
            size_t value_len = env_len - search_len;
            if (value_len < value_size) {
                strncpy(value_out, ptr + search_len, value_len);
                value_out[value_len] = '\0';
                fprintf(stderr, "    Found %s=%s (env var #%d)\n", env_name, value_out, env_count);
                free(proc_data);
                return true;
            }
        }
        ptr += env_len + 1;
    }

    fprintf(stderr, "    Checked %d environment variables, no %s found\n", env_count, env_name);
    free(proc_data);
    return false;
}

// Function to concatenate paths
// Assumes output_path is PATH_MAX bytes
static void concatenate_path(const char* original_path, const char* wrapper_value, char* output_path) {
    // Special case: if original_path is just "/", return the wrapper_value directory
    if (strcmp(original_path, "/") == 0) {
        strncpy(output_path, wrapper_value, PATH_MAX - 1);
        output_path[PATH_MAX - 1] = '\0';
        return;
    }

    // If wrapper_value ends with '/', remove it to avoid double slashes
    size_t wrapper_len = strlen(wrapper_value);
    if (wrapper_len > 0 && wrapper_value[wrapper_len - 1] == '/') {
        snprintf(output_path, PATH_MAX, "%.*s%s",
                (int)(wrapper_len - 1), wrapper_value, original_path);
    } else {
        snprintf(output_path, PATH_MAX, "%s%s",
                wrapper_value, original_path);
    }
}

// Helper function to create parent directories for a file path (like mkdir -p)
static void create_parent_directories(const char* file_path) {
    char tmp[PATH_MAX];
    strncpy(tmp, file_path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    // Get calling process context for ownership
    struct fuse_context *context = fuse_get_context();

    char *last_slash = strrchr(tmp, '/');
    if (last_slash && last_slash != tmp) {
        *last_slash = '\0';

        // mkdir -p implementation
        for (char *p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                if (mkdir(tmp, 0755) == 0 && context) {
                    // Set ownership to calling process
                    chown(tmp, context->uid, context->gid);
                }
                *p = '/';
            }
        }
        if (mkdir(tmp, 0755) == 0 && context) {
            // Set ownership to calling process
            chown(tmp, context->uid, context->gid);
        }
    }
}

// Helper function to remove whiteout marker when creating a new file/directory
static void remove_whiteout_marker(const char* upper_dir, const char* path) {
    char whiteout_path[PATH_MAX];
    snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted%s", upper_dir, path);
    struct stat st;
    if (lstat(whiteout_path, &st) == 0 && S_ISREG(st.st_mode)) {
        fprintf(stderr, "    -> Removing whiteout marker: %s\n", whiteout_path);
        unlink(whiteout_path);
    }
}

// Function to determine where a file exists in the overlay
static overlay_location_t find_overlay_file_location(const char* original_path, const struct overlay_info* overlay,
                                                     char* upper_path, char* lower_path) {
    struct stat st;

    // Build paths for upper and lower locations using the provided buffers
    concatenate_path(original_path, overlay->upper_dir, upper_path);
    concatenate_path(original_path, overlay->lower_dir, lower_path);

    char whiteout_path[PATH_MAX];

    // Whiteout path: upper_dir/.deleted/original_path
    if (strcmp(original_path, "/") == 0) {
        snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted", overlay->upper_dir);
    } else {
        snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted%s", overlay->upper_dir, original_path);
    }

    fprintf(stderr, "    Checking overlay locations for %s:\n", original_path);
    fprintf(stderr, "      Upper: %s\n", upper_path);
    fprintf(stderr, "      Lower: %s\n", lower_path);
    fprintf(stderr, "      Whiteout: %s\n", whiteout_path);

    // 1. Check if file is whiteout (deleted)
    // Important: whiteout markers are regular files, not directories
    // The .deleted directory structure itself is not a whiteout
    if (lstat(whiteout_path, &st) == 0 && S_ISREG(st.st_mode)) {
        fprintf(stderr, "      -> WHITEOUT (file deleted)\n");
        return OVERLAY_WHITEOUT;
    }

    // 2. Check upper layer first
    if (lstat(upper_path, &st) == 0) {
        fprintf(stderr, "      -> UPPER (found in upper layer)\n");
        return OVERLAY_UPPER;
    }

    // 3. Check lower layer
    if (lstat(lower_path, &st) == 0) {
        fprintf(stderr, "      -> LOWER (found in lower layer)\n");
        return OVERLAY_LOWER;
    }

    // 4. File doesn't exist anywhere
    fprintf(stderr, "      -> NONE (file not found)\n");
    return OVERLAY_NONE;
}

// Forward declarations
static struct overlay_info find_overlay_in_tree(pid_t starting_pid);
static int copy_file_to_upper(const char* lower_path, const char* upper_path);

// Helper function to apply wrapper detection and path redirection
// Helper function to check if we should block fseventsd
static bool should_block_fseventsd(struct fuse_context *context, const char* operation_name) {
    if (!context) {
        return false;
    }

    char proc_name[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(context->pid, proc_name, sizeof(proc_name)) > 0) {
        char *basename = strrchr(proc_name, '/');
        basename = basename ? basename + 1 : proc_name;

        if (strcmp(basename, "fseventsd") == 0) {
            fprintf(stderr, "*** %s BLOCKING fseventsd PID %d ***\n", operation_name, context->pid);
            return true;
        }
    }
    return false;
}

// Helper function to get the passthrough path (backup or original)
static void get_passthrough_path(const char* original_path, char* result_path) {
    if (loopback.backup_created) {
        concatenate_path(original_path, loopback.backup_path, result_path);
        fprintf(stderr, "*** PASSTHROUGH: %s -> %s ***\n", original_path, result_path);
    } else {
        strncpy(result_path, original_path, PATH_MAX - 1);
        result_path[PATH_MAX - 1] = '\0';
    }
}

// Function to find WRAPPER_UPPER and WRAPPER_LOWER environment variables in process tree
static struct overlay_info find_overlay_in_tree(pid_t starting_pid) {
    struct overlay_info result = { .found = 0, .pid = -1, .upper_dir = "", .lower_dir = "" };
    pid_t current_pid = starting_pid;
    int depth = 0;

    fprintf(stderr, "Searching for WRAPPER_UPPER/WRAPPER_LOWER in process tree starting from PID %d:\n", starting_pid);

    while (current_pid > 1 && depth < 10) {
        // Check if this process has WRAPPER_UPPER and WRAPPER_LOWER in its environment variables
        // Write directly into result struct to avoid intermediate copies
        bool has_upper = get_env_from_process(current_pid, "WRAPPER_UPPER", result.upper_dir, sizeof(result.upper_dir));
        bool has_lower = get_env_from_process(current_pid, "WRAPPER_LOWER", result.lower_dir, sizeof(result.lower_dir));

        fprintf(stderr, "  PID %d: upper=%s, lower=%s\n",
                current_pid,
                has_upper ? "YES" : "no",
                has_lower ? "YES" : "no");

        if (has_upper && has_lower) {
            result.found = 1;
            result.pid = current_pid;
            fprintf(stderr, "Found WRAPPER_UPPER=%s WRAPPER_LOWER=%s at PID %d!\n", result.upper_dir, result.lower_dir, current_pid);
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

static int
loopback_getattr(const char *path, struct stat *stbuf)
{
    int res;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "GETATTR")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** GETATTR OVERLAY: %s ***\n", path);

        // Find the file location in overlay
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                fprintf(stderr, "    -> Reading attributes from UPPER: %s\n", upper_path);
                res = lstat(upper_path, stbuf);
                break;

            case OVERLAY_LOWER:
                fprintf(stderr, "    -> Reading attributes from LOWER: %s\n", lower_path);
                res = lstat(lower_path, stbuf);
                break;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File not found\n");
                return -ENOENT;
        }

        if (res == -1) {
            return -errno;
        }

        stbuf->st_blksize = 0;
        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    res = lstat(redirected, stbuf);

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
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "FGETATTR")) {
        return -ENOTSUP;
    }

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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "ACCESS")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** ACCESS OVERLAY: %s (mask=%d) ***\n", path, mask);

        // Find the file location in overlay
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                fprintf(stderr, "    -> Checking access from UPPER: %s\n", upper_path);
                res = access(upper_path, mask & (F_OK | X_OK | W_OK | R_OK));
                break;

            case OVERLAY_LOWER:
                fprintf(stderr, "    -> Checking access from LOWER: %s\n", lower_path);
                res = access(lower_path, mask & (F_OK | X_OK | W_OK | R_OK));
                break;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File not found\n");
                return -ENOENT;
        }

        if (res == -1) {
            return -errno;
        }

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

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

    res = access(redirected, mask & (F_OK | X_OK | W_OK | R_OK));
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "READLINK")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** READLINK OVERLAY: %s ***\n", path);

        // Find the symlink location in overlay
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> Symlink is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                fprintf(stderr, "    -> Reading symlink from UPPER: %s\n", upper_path);
                res = readlink(upper_path, buf, size - 1);
                if (res == -1) {
                    return -errno;
                }
                buf[res] = '\0';
                return 0;

            case OVERLAY_LOWER:
                fprintf(stderr, "    -> Reading symlink from LOWER: %s\n", lower_path);
                res = readlink(lower_path, buf, size - 1);
                if (res == -1) {
                    return -errno;
                }
                buf[res] = '\0';
                return 0;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> Symlink not found\n");
                return -ENOENT;
        }
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    res = readlink(redirected, buf, size - 1);
    if (res == -1) {
        return -errno;
    }

    buf[res] = '\0';

    return 0;
}

// Passthrough directory structure (non-overlay mode)
struct loopback_dirp {
    bool is_overlay;     // Always false for passthrough mode
    DIR *dp;
    struct dirent *entry;
    off_t offset;
};

// Overlay directory structure (overlay mode)
struct overlay_dirp {
    bool is_overlay;                    // Always true for overlay mode
    char **merged_entries;              // Array of directory entry names (always used)
    int entry_count;                    // Number of entries
    int current_index;                  // Current position for iteration
    struct overlay_info overlay_info;   // Store overlay info for this directory
    char original_path[PATH_MAX];       // Original requested path
};

// Union for type-safe directory handle discrimination
// Both structs have is_overlay as first field, so we can check either one
union fuse_dirp {
    struct loopback_dirp loopback;
    struct overlay_dirp overlay;
};

// Helper function to free an array of strings
static void free_string_array(char** array, int count) {
    if (!array) return;
    for (int i = 0; i < count; i++) {
        free(array[i]);
    }
    free(array);
}

// Helper function to grow a string array using realloc
// Returns 0 on success, -ENOMEM on failure
static int grow_string_array(char*** array, int* capacity) {
    int new_capacity = (*capacity) * 2;
    char** new_array = realloc(*array, new_capacity * sizeof(char*));
    if (!new_array) {
        return -ENOMEM;
    }
    *array = new_array;
    *capacity = new_capacity;
    return 0;
}

// Function to merge directory entries from upper and lower layers
static int merge_overlay_directory_entries(const char* original_path, const struct overlay_info* overlay,
                                           char*** entries, int* entry_count) {
    char upper_path_buf[PATH_MAX], lower_path_buf[PATH_MAX];
    concatenate_path(original_path, overlay->upper_dir, upper_path_buf);
    concatenate_path(original_path, overlay->lower_dir, lower_path_buf);

    // Whiteout directory path
    char whiteout_path[PATH_MAX];
    if (strcmp(original_path, "/") == 0) {
        snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted", overlay->upper_dir);
    } else {
        snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted%s", overlay->upper_dir, original_path);
    }

    fprintf(stderr, "    Merging directory entries for %s:\n", original_path);
    fprintf(stderr, "      Upper dir: %s\n", upper_path_buf);
    fprintf(stderr, "      Lower dir: %s\n", lower_path_buf);
    fprintf(stderr, "      Whiteout dir: %s\n", whiteout_path);

    // Dynamic allocation with realloc - start with reasonable initial capacity
    int entries_capacity = 256;
    *entries = malloc(entries_capacity * sizeof(char*));
    if (!*entries) {
        return -ENOMEM;
    }
    *entry_count = 0;

    // Track which files we've seen to avoid duplicates (upper takes precedence)
    int seen_capacity = 256;
    char **seen_files = malloc(seen_capacity * sizeof(char*));
    if (!seen_files) {
        free(*entries);
        return -ENOMEM;
    }
    int seen_count = 0;

    // Read whiteout directory to get list of deleted files
    // Important: only regular files in .deleted are whiteout markers
    // Directories in .deleted are just structure to hold nested whiteout markers
    int whiteout_capacity = 256;
    char **whiteout_files = malloc(whiteout_capacity * sizeof(char*));
    if (!whiteout_files) {
        free(seen_files);
        free(*entries);
        return -ENOMEM;
    }
    int whiteout_count = 0;
    DIR* whiteout_dp = opendir(whiteout_path);
    if (whiteout_dp) {
        struct dirent* entry;
        while ((entry = readdir(whiteout_dp))) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Check if this is a regular file (whiteout marker) or directory (structure)
                char full_whiteout_path[PATH_MAX];
                snprintf(full_whiteout_path, sizeof(full_whiteout_path), "%s/%s", whiteout_path, entry->d_name);

                struct stat whiteout_st;
                if (lstat(full_whiteout_path, &whiteout_st) == 0 && S_ISREG(whiteout_st.st_mode)) {
                    // Grow array if needed
                    if (whiteout_count >= whiteout_capacity) {
                        if (grow_string_array(&whiteout_files, &whiteout_capacity) != 0) {
                            free_string_array(whiteout_files, whiteout_count);
                            free_string_array(seen_files, seen_count);
                            free(*entries);
                            closedir(whiteout_dp);
                            return -ENOMEM;
                        }
                    }

                    // Only add regular files as whiteout markers
                    whiteout_files[whiteout_count] = strdup(entry->d_name);
                    whiteout_count++;
                }
            }
        }
        closedir(whiteout_dp);
    }


    // First, read upper directory
    DIR* upper_dp = opendir(upper_path_buf);
    if (upper_dp) {
        struct dirent* entry;
        while ((entry = readdir(upper_dp))) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Skip .deleted directory itself
                if (strcmp(entry->d_name, ".deleted") == 0) {
                    continue;
                }

                // Grow entries array if needed
                if (*entry_count >= entries_capacity) {
                    if (grow_string_array(entries, &entries_capacity) != 0) {
                        free_string_array(*entries, *entry_count);
                        free_string_array(seen_files, seen_count);
                        free_string_array(whiteout_files, whiteout_count);
                        closedir(upper_dp);
                        return -ENOMEM;
                    }
                }

                // Grow seen_files array if needed
                if (seen_count >= seen_capacity) {
                    if (grow_string_array(&seen_files, &seen_capacity) != 0) {
                        free_string_array(*entries, *entry_count);
                        free_string_array(seen_files, seen_count);
                        free_string_array(whiteout_files, whiteout_count);
                        closedir(upper_dp);
                        return -ENOMEM;
                    }
                }

                (*entries)[*entry_count] = strdup(entry->d_name);
                seen_files[seen_count] = strdup(entry->d_name);
                seen_count++;
                (*entry_count)++;
                fprintf(stderr, "        Added from upper: %s\n", entry->d_name);
            }
        }
        closedir(upper_dp);
    }

    // Then, read lower directory (only add files not in upper and not whiteout)
    DIR* lower_dp = opendir(lower_path_buf);
    if (lower_dp) {
        struct dirent* entry;
        while ((entry = readdir(lower_dp))) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Check if already seen (upper takes precedence)
                bool found_in_upper = false;
                for (int i = 0; i < seen_count; i++) {
                    if (strcmp(seen_files[i], entry->d_name) == 0) {
                        found_in_upper = true;
                        break;
                    }
                }

                // Check if whiteout (deleted)
                bool is_whiteout = false;
                for (int i = 0; i < whiteout_count; i++) {
                    if (strcmp(whiteout_files[i], entry->d_name) == 0) {
                        is_whiteout = true;
                        break;
                    }
                }

                if (!found_in_upper && !is_whiteout) {
                    // Grow entries array if needed
                    if (*entry_count >= entries_capacity) {
                        if (grow_string_array(entries, &entries_capacity) != 0) {
                            free_string_array(*entries, *entry_count);
                            free_string_array(seen_files, seen_count);
                            free_string_array(whiteout_files, whiteout_count);
                            closedir(lower_dp);
                            return -ENOMEM;
                        }
                    }

                    (*entries)[*entry_count] = strdup(entry->d_name);
                    (*entry_count)++;
                    fprintf(stderr, "        Added from lower: %s\n", entry->d_name);
                }
            }
        }
        closedir(lower_dp);
    }

    fprintf(stderr, "      Total merged entries: %d\n", *entry_count);

    // Free temporary tracking arrays
    free_string_array(seen_files, seen_count);
    free_string_array(whiteout_files, whiteout_count);

    return 0;
}

// Helper function to recursively remove a directory and all its contents
static int remove_directory_recursive(const char* path) {
    DIR *dir = opendir(path);
    if (!dir) {
        return -1;
    }

    struct dirent *entry;
    int failed = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char entry_path[PATH_MAX];
        snprintf(entry_path, sizeof(entry_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (lstat(entry_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                // Recursively remove subdirectory
                if (remove_directory_recursive(entry_path) != 0) {
                    failed = 1;
                }
            } else {
                // Remove file
                if (unlink(entry_path) != 0) {
                    fprintf(stderr, "Failed to unlink %s: %s\n", entry_path, strerror(errno));
                    failed = 1;
                }
            }
        }
    }

    closedir(dir);

    // Remove the directory itself
    if (rmdir(path) != 0) {
        fprintf(stderr, "Failed to rmdir %s: %s\n", path, strerror(errno));
        failed = 1;
    }

    return failed ? -1 : 0;
}

// Helper function to create whiteout marker for overlay deletes
static int create_whiteout_marker(const char* original_path, const struct overlay_info* overlay) {
    char whiteout_dir[PATH_MAX];
    char whiteout_file[PATH_MAX];
    char *dir_path, *file_name;

    // Build whiteout directory path
    if (strcmp(original_path, "/") == 0) {
        return -EINVAL;  // Can't delete root
    }

    // Extract directory and filename
    char path_copy[PATH_MAX];
    strncpy(path_copy, original_path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';

    file_name = strrchr(path_copy, '/');
    if (!file_name) {
        return -EINVAL;
    }

    *file_name = '\0';  // Split the path
    file_name++;        // Move past the '/'
    dir_path = path_copy;

    if (strlen(dir_path) == 0) {
        dir_path = "/";
    }

    // Build whiteout directory: upper_dir/.deleted/dir_path
    if (strcmp(dir_path, "/") == 0) {
        snprintf(whiteout_dir, sizeof(whiteout_dir), "%s/.deleted", overlay->upper_dir);
    } else {
        snprintf(whiteout_dir, sizeof(whiteout_dir), "%s/.deleted%s", overlay->upper_dir, dir_path);
    }

    // Build whiteout file path
    snprintf(whiteout_file, sizeof(whiteout_file), "%s/%s", whiteout_dir, file_name);

    fprintf(stderr, "    Creating whiteout marker: %s\n", whiteout_file);

    // Create whiteout directory if it doesn't exist
    create_parent_directories(whiteout_file);

    // Check if whiteout_file already exists as a directory
    // This happens when we previously deleted files within this directory
    // Now we're deleting the directory itself, so we need to replace
    // the directory (containing child whiteout markers) with a single file marker
    struct stat st;
    if (lstat(whiteout_file, &st) == 0 && S_ISDIR(st.st_mode)) {
        fprintf(stderr, "    Whiteout path exists as directory, removing recursively: %s\n", whiteout_file);
        if (remove_directory_recursive(whiteout_file) != 0) {
            fprintf(stderr, "    Warning: Failed to fully remove whiteout directory: %s\n", whiteout_file);
            // Continue anyway - try to create the file marker
        }
    }

    // Create whiteout marker file (empty file)
    // If a file already exists here, creat() will truncate it (which is fine - same effect)
    int fd = creat(whiteout_file, 0644);
    if (fd < 0) {
        return -errno;
    }
    close(fd);

    return 0;
}

static int
loopback_opendir(const char *path, struct fuse_file_info *fi)
{
    int res;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "OPENDIR")) {
        return -ENOTSUP;
    }

    // Check for overlay configuration
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found && strlen(overlay.upper_dir) > 0) {
        // Allocate union for overlay mode
        union fuse_dirp *dirp = malloc(sizeof(union fuse_dirp));
        if (dirp == NULL) {
            return -ENOMEM;
        }

        // Initialize overlay_dirp fields
        dirp->overlay.is_overlay = true;
        dirp->overlay.overlay_info = overlay;
        dirp->overlay.current_index = 0;
        dirp->overlay.merged_entries = NULL;
        dirp->overlay.entry_count = 0;
        strncpy(dirp->overlay.original_path, path, sizeof(dirp->overlay.original_path) - 1);
        dirp->overlay.original_path[sizeof(dirp->overlay.original_path) - 1] = '\0';

        // Check if directory exists in upper, lower, or has whiteout marker
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        concatenate_path(path, overlay.upper_dir, upper_path);
        concatenate_path(path, overlay.lower_dir, lower_path);

        // Check for whiteout marker first
        char whiteout_path[PATH_MAX];
        if (strcmp(path, "/") == 0) {
            snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted", overlay.upper_dir);
        } else {
            snprintf(whiteout_path, sizeof(whiteout_path), "%s/.deleted%s", overlay.upper_dir, path);
        }

        struct stat whiteout_st;
        if (lstat(whiteout_path, &whiteout_st) == 0 && S_ISREG(whiteout_st.st_mode)) {
            // Whiteout marker exists - directory is deleted
            free(dirp);
            return -ENOENT;
        }

        struct stat upper_st, lower_st;
        bool exists_upper = (lstat(upper_path, &upper_st) == 0 && S_ISDIR(upper_st.st_mode));
        bool exists_lower = (lstat(lower_path, &lower_st) == 0 && S_ISDIR(lower_st.st_mode));

        if (!exists_upper && !exists_lower) {
            // Directory doesn't exist in either layer
            free(dirp);
            return -ENOENT;
        }

        // Always build merged_entries array (handles both single-layer and merged cases)
        res = merge_overlay_directory_entries(path, &overlay, &dirp->overlay.merged_entries, &dirp->overlay.entry_count);
        if (res < 0) {
            free(dirp);
            return res;
        }

        fi->fh = (unsigned long)dirp;
        return 0;
    }

    // Fall back to regular passthrough directory handling
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    union fuse_dirp *dirp = malloc(sizeof(union fuse_dirp));
    if (dirp == NULL) {
        return -ENOMEM;
    }

    dirp->loopback.is_overlay = false;
    dirp->loopback.dp = opendir(redirected);
    if (dirp->loopback.dp == NULL) {
        res = -errno;
        free(dirp);
        return res;
    }

    dirp->loopback.offset = 0;
    dirp->loopback.entry = NULL;

    fi->fh = (unsigned long)dirp;

    return 0;
}

static int
loopback_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                 off_t offset, struct fuse_file_info *fi)
{
    union fuse_dirp *dirp = (union fuse_dirp *)(uintptr_t)fi->fh;

    if (dirp->loopback.is_overlay) {
        // Overlay directory - use cached entry list (always)
        struct overlay_dirp *od = &dirp->overlay;

        // If offset is 0, rebuild the directory entries (like rewinddir for regular dirs)
        if (offset == 0) {
            // Free old entries
            for (int i = 0; i < od->entry_count; i++) {
                free(od->merged_entries[i]);
            }
            free(od->merged_entries);

            // Rebuild merged entries
            int res = merge_overlay_directory_entries(od->original_path, &od->overlay_info,
                                                      &od->merged_entries, &od->entry_count);
            if (res < 0) {
                return res;
            }
            od->current_index = 0;
        }

        // Handle overlay directory - merged listing
        fprintf(stderr, "    Reading overlay directory: %s (offset=%lld, entries=%d)\n",
                od->original_path, (long long)offset, od->entry_count);

        // Add . and .. entries first
        if (offset == 0) {
            struct stat st;
            memset(&st, 0, sizeof(st));
            st.st_mode = S_IFDIR;
            if (filler(buf, ".", &st, 1)) {
                return 0;
            }
        }
        if (offset <= 1) {
            struct stat st;
            memset(&st, 0, sizeof(st));
            st.st_mode = S_IFDIR;
            if (filler(buf, "..", &st, 2)) {
                return 0;
            }
        }

        // Add merged entries starting from offset-2 (accounting for . and ..)
        int start_index = (offset <= 2) ? 0 : (offset - 2);
        for (int i = start_index; i < od->entry_count; i++) {
            struct stat st;
            memset(&st, 0, sizeof(st));
            st.st_mode = S_IFREG;  // Default to regular file

            // Try to get real stat info by constructing full path
            char full_path[PATH_MAX];
            if (strcmp(od->original_path, "/") == 0) {
                snprintf(full_path, sizeof(full_path), "/%s", od->merged_entries[i]);
            } else {
                snprintf(full_path, sizeof(full_path), "%s/%s", od->original_path, od->merged_entries[i]);
            }

            // Use overlay logic to find the file in upper/lower layers and get its stats
            char upper_path[PATH_MAX], lower_path[PATH_MAX];
            overlay_location_t location = find_overlay_file_location(full_path, &od->overlay_info, upper_path, lower_path);

            if (location == OVERLAY_UPPER) {
                lstat(upper_path, &st);
            } else if (location == OVERLAY_LOWER) {
                lstat(lower_path, &st);
            }
            // If not found or whiteout, keep default st.st_mode = S_IFREG

            off_t nextoff = i + 3;  // +3 for ., .., and 0-based index
            if (filler(buf, od->merged_entries[i], &st, nextoff)) {
                break;
            }
        }

        return 0;
    } else {
        // Passthrough directory - use regular DIR* pointer
        struct loopback_dirp *d = &dirp->loopback;

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
}

static int
loopback_releasedir(const char *path, struct fuse_file_info *fi)
{
    union fuse_dirp *dirp = (union fuse_dirp *)(uintptr_t)fi->fh;

    (void)path;

    if (dirp->loopback.is_overlay) {
        // Handle overlay directory cleanup
        struct overlay_dirp *od = &dirp->overlay;
        fprintf(stderr, "    Releasing overlay directory: %s (%d entries)\n",
                od->original_path, od->entry_count);

        // Free all the allocated entry names
        for (int i = 0; i < od->entry_count; i++) {
            free(od->merged_entries[i]);
        }
        // Free the entries array
        free(od->merged_entries);

        free(dirp);
    } else {
        // Handle passthrough directory cleanup
        struct loopback_dirp *d = &dirp->loopback;
        closedir(d->dp);
        free(dirp);
    }

    return 0;
}

static int
loopback_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "MKNOD")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** MKNOD OVERLAY: %s (mode=%o) ***\n", path, mode);

        // Special files are always created in upper layer (write operation)
        char upper_path[PATH_MAX];
        concatenate_path(path, overlay.upper_dir, upper_path);

        fprintf(stderr, "    -> Creating special file in UPPER: %s\n", upper_path);

        // Create parent directories in upper layer if needed
        create_parent_directories(upper_path);

        // Create the special file in upper layer
        if (S_ISFIFO(mode)) {
            res = mkfifo(upper_path, mode);
        } else {
            res = mknod(upper_path, mode, rdev);
        }

        if (res == -1) {
            fprintf(stderr, "    -> Failed to create special file: %s\n", strerror(errno));
            return -errno;
        }

        // Set proper ownership to the calling user
        if (context && chown(upper_path, context->uid, context->gid) == -1) {
            fprintf(stderr, "    Warning: Failed to set ownership for %s: %s\n", upper_path, strerror(errno));
        }

        // If there's a whiteout marker, remove it since we're creating a real file
        remove_whiteout_marker(overlay.upper_dir, path);

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    if (S_ISFIFO(mode)) {
        res = mkfifo(redirected, mode);
    } else {
        res = mknod(redirected, mode, rdev);
    }

    if (res == -1) {
        return -errno;
    }

    // Set proper ownership to the calling user
    if (context && chown(redirected, context->uid, context->gid) == -1) {
        fprintf(stderr, "Warning: Failed to set ownership for %s: %s\n", redirected, strerror(errno));
    }

    return 0;
}

static int
loopback_mkdir(const char *path, mode_t mode)
{
    int res;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "MKDIR")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** MKDIR OVERLAY: %s ***\n", path);

        // Directories are always created in upper layer (write operation)
        char upper_path[PATH_MAX];
        concatenate_path(path, overlay.upper_dir, upper_path);

        fprintf(stderr, "    -> Creating directory in UPPER: %s\n", upper_path);

        // Create parent directories in upper layer if needed
        create_parent_directories(upper_path);

        // Create the directory in upper layer
        res = mkdir(upper_path, mode);
        if (res == -1) {
            fprintf(stderr, "    -> Failed to create directory: %s\n", strerror(errno));
            return -errno;
        }

        // Set proper ownership to the calling user
        if (context && chown(upper_path, context->uid, context->gid) == -1) {
            fprintf(stderr, "    Warning: Failed to set ownership for %s: %s\n", upper_path, strerror(errno));
        }

        // If there's a whiteout marker, remove it since we're creating a real directory
        remove_whiteout_marker(overlay.upper_dir, path);

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    res = mkdir(redirected, mode);
    if (res == -1) {
        return -errno;
    }

    // Set proper ownership to the calling user
    if (context && chown(redirected, context->uid, context->gid) == -1) {
        fprintf(stderr, "Warning: Failed to set ownership for %s: %s\n", redirected, strerror(errno));
    }

    return 0;
}

static int
loopback_unlink(const char *path)
{
    int res;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "UNLINK")) {
        return -ENOTSUP;
    }

    // Check for overlay configuration
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found && strlen(overlay.upper_dir) > 0) {
        // This is an overlay filesystem - use overlay delete logic
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        switch (location) {
            case OVERLAY_WHITEOUT:
                // File already deleted (whiteout exists)
                fprintf(stderr, "*** UNLINK OVERLAY: %s already whiteout (deleted) ***\n", path);
                return -ENOENT;

            case OVERLAY_UPPER:
                // File exists in upper layer - delete it
                {
                    fprintf(stderr, "*** UNLINK OVERLAY UPPER: %s -> delete %s ***\n", path, upper_path);
                    res = unlink(upper_path);
                    if (res == -1) {
                        return -errno;
                    }

                    // Check if file also exists in lower layer
                    struct stat lower_st;
                    if (lstat(lower_path, &lower_st) == 0) {
                        // File exists in lower - create whiteout marker to hide it
                        fprintf(stderr, "    -> File also in lower, creating whiteout marker\n");
                        res = create_whiteout_marker(path, &overlay);
                        if (res < 0) {
                            return res;
                        }
                    }
                    return 0;
                }

            case OVERLAY_LOWER:
                // File exists only in lower layer - create whiteout marker
                fprintf(stderr, "*** UNLINK OVERLAY LOWER: %s -> create whiteout ***\n", path);
                res = create_whiteout_marker(path, &overlay);
                if (res < 0) {
                    return res;
                }
                return 0;

            case OVERLAY_NONE:
                // File doesn't exist anywhere
                fprintf(stderr, "*** UNLINK OVERLAY NONE: %s does not exist ***\n", path);
                return -ENOENT;
        }
    }

    // Fall back to regular unlink
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    res = unlink(redirected);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "RMDIR")) {
        return -ENOTSUP;
    }

    // Check for overlay configuration
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found && strlen(overlay.upper_dir) > 0) {
        // This is an overlay filesystem - use overlay delete logic
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        switch (location) {
            case OVERLAY_WHITEOUT:
                // Directory already deleted (whiteout exists)
                fprintf(stderr, "*** RMDIR OVERLAY: %s already whiteout (deleted) ***\n", path);
                return -ENOENT;

            case OVERLAY_UPPER:
                // Directory exists in upper layer - delete it
                {
                    fprintf(stderr, "*** RMDIR OVERLAY UPPER: %s -> delete %s ***\n", path, upper_path);
                    res = rmdir(upper_path);
                    if (res == -1) {
                        return -errno;
                    }

                    // Check if directory also exists in lower layer
                    struct stat lower_st;
                    if (lstat(lower_path, &lower_st) == 0 && S_ISDIR(lower_st.st_mode)) {
                        // Directory exists in lower - create whiteout marker to hide it
                        fprintf(stderr, "    -> Directory also in lower, creating whiteout marker\n");
                        res = create_whiteout_marker(path, &overlay);
                        if (res < 0) {
                            return res;
                        }
                    }
                    return 0;
                }

            case OVERLAY_LOWER:
                // Directory exists only in lower layer - create whiteout marker
                fprintf(stderr, "*** RMDIR OVERLAY LOWER: %s -> create whiteout ***\n", path);
                res = create_whiteout_marker(path, &overlay);
                if (res < 0) {
                    return res;
                }
                return 0;

            case OVERLAY_NONE:
                // Directory doesn't exist anywhere
                fprintf(stderr, "*** RMDIR OVERLAY NONE: %s does not exist ***\n", path);
                return -ENOENT;
        }
    }

    // Fall back to regular rmdir
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    res = rmdir(redirected);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "SYMLINK")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** SYMLINK OVERLAY: %s -> %s ***\n", to, from);

        // Symlinks are always created in upper layer (write operation)
        char upper_path[PATH_MAX];
        concatenate_path(to, overlay.upper_dir, upper_path);

        fprintf(stderr, "    -> Creating symlink in UPPER: %s\n", upper_path);

        // Create parent directories in upper layer if needed
        create_parent_directories(upper_path);

        // Create the symlink in upper layer
        res = symlink(from, upper_path);
        if (res == -1) {
            fprintf(stderr, "    -> Failed to create symlink: %s\n", strerror(errno));
            return -errno;
        }

        // Set ownership to calling user (new file creation)
        if (context && lchown(upper_path, context->uid, context->gid) == -1) {
            fprintf(stderr, "    Warning: Failed to set symlink ownership: %s\n", strerror(errno));
        }

        // If there's a whiteout marker, remove it since we're creating a real file
        remove_whiteout_marker(overlay.upper_dir, to);

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(to, redirected);

    res = symlink(from, redirected);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "RENAME")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** RENAME OVERLAY: %s -> %s ***\n", from, to);

        // Find locations of source and destination
        char from_upper[PATH_MAX], from_lower[PATH_MAX];
        char to_upper[PATH_MAX], to_lower[PATH_MAX];
        overlay_location_t from_loc = find_overlay_file_location(from, &overlay, from_upper, from_lower);
        overlay_location_t to_loc = find_overlay_file_location(to, &overlay, to_upper, to_lower);

        // Check if source exists
        if (from_loc == OVERLAY_WHITEOUT || from_loc == OVERLAY_NONE) {
            fprintf(stderr, "    -> Source file does not exist\n");
            return -ENOENT;
        }

        // Handle source file based on its location
        if (from_loc == OVERLAY_LOWER) {
            fprintf(stderr, "    -> Source is in LOWER, copying to UPPER at new location\n");
            create_parent_directories(to_upper);
            if (copy_file_to_upper(from_lower, to_upper) != 0) {
                fprintf(stderr, "    -> Failed to copy source to upper\n");
                return -EIO;
            }

            // Create whiteout marker at old location (to hide lower file)
            create_whiteout_marker(from, &overlay);
        } else {
            // Source is in upper - perform normal rename
            fprintf(stderr, "    -> Source is in UPPER, renaming\n");
            create_parent_directories(to_upper);
            res = rename(from_upper, to_upper);
            if (res == -1) {
                fprintf(stderr, "    -> Rename failed: %s\n", strerror(errno));
                return -errno;
            }
        }

        // If destination exists in lower layer, create whiteout marker
        if (to_loc == OVERLAY_LOWER) {
            fprintf(stderr, "    -> Destination exists in LOWER, will be hidden by new file\n");
        }

        // Remove any whiteout marker at destination
        remove_whiteout_marker(overlay.upper_dir, to);

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected_from[PATH_MAX];
    char redirected_to[PATH_MAX];
    get_passthrough_path(from, redirected_from);
    get_passthrough_path(to, redirected_to);

    res = rename(redirected_from, redirected_to);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "EXCHANGE")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** EXCHANGE OVERLAY: %s <-> %s ***\n", path1, path2);

        // Find locations of both files
        char path1_upper[PATH_MAX], path1_lower[PATH_MAX];
        char path2_upper[PATH_MAX], path2_lower[PATH_MAX];
        overlay_location_t loc1 = find_overlay_file_location(path1, &overlay, path1_upper, path1_lower);
        overlay_location_t loc2 = find_overlay_file_location(path2, &overlay, path2_upper, path2_lower);

        // Check if files exist
        if (loc1 == OVERLAY_WHITEOUT || loc1 == OVERLAY_NONE) {
            fprintf(stderr, "    -> path1 does not exist\n");
            return -ENOENT;
        }
        if (loc2 == OVERLAY_WHITEOUT || loc2 == OVERLAY_NONE) {
            fprintf(stderr, "    -> path2 does not exist\n");
            return -ENOENT;
        }

        // Copy up path1 if needed
        if (loc1 == OVERLAY_LOWER) {
            fprintf(stderr, "    -> Copying up path1 from LOWER to UPPER\n");
            create_parent_directories(path1_upper);
            if (copy_file_to_upper(path1_lower, path1_upper) != 0) {
                fprintf(stderr, "    -> Failed to copy up path1\n");
                return -EIO;
            }
        }

        // Copy up path2 if needed
        if (loc2 == OVERLAY_LOWER) {
            fprintf(stderr, "    -> Copying up path2 from LOWER to UPPER\n");
            create_parent_directories(path2_upper);
            if (copy_file_to_upper(path2_lower, path2_upper) != 0) {
                fprintf(stderr, "    -> Failed to copy up path2\n");
                return -EIO;
            }
        }

        // Both files are now in upper layer - perform the exchange
        fprintf(stderr, "    -> Exchanging files in UPPER layer\n");
        res = exchangedata(path1_upper, path2_upper, options);
        if (res == -1) {
            fprintf(stderr, "    -> Exchange failed: %s\n", strerror(errno));
            return -errno;
        }

        // Remove any whiteout markers
        remove_whiteout_marker(overlay.upper_dir, path1);
        remove_whiteout_marker(overlay.upper_dir, path2);

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected1[PATH_MAX];
    char redirected2[PATH_MAX];
    get_passthrough_path(path1, redirected1);
    get_passthrough_path(path2, redirected2);

    res = exchangedata(redirected1, redirected2, options);
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
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "LINK")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** LINK OVERLAY: %s -> %s ***\n", from, to);

        // Find the source file location
        char from_upper_path[PATH_MAX], from_lower_path[PATH_MAX];
        overlay_location_t from_location = find_overlay_file_location(from, &overlay, from_upper_path, from_lower_path);

        const char *from_real_path;
        switch (from_location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> Source file is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> Source file does not exist\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                from_real_path = from_upper_path;
                break;

            case OVERLAY_LOWER:
                from_real_path = from_lower_path;
                break;
        }

        // Destination is always in upper layer (write operation)
        char to_upper_path[PATH_MAX];
        concatenate_path(to, overlay.upper_dir, to_upper_path);

        // Create parent directories in upper layer if needed
        create_parent_directories(to_upper_path);

        // If source is in lower layer, we need to copy it to upper first
        // (can't create hard links across different filesystems)
        char from_upper_path_buf[PATH_MAX];
        const char *from_link_path;

        if (from_location == OVERLAY_LOWER) {
            fprintf(stderr, "    -> Source in LOWER, copying to UPPER first\n");
            concatenate_path(from, overlay.upper_dir, from_upper_path_buf);

            // Copy the file from lower to upper (breaking any existing hard links)
            res = copy_file_to_upper(from_real_path, from_upper_path_buf);
            if (res < 0) {
                fprintf(stderr, "    -> Failed to copy file to upper: %d\n", res);
                return res;
            }

            from_link_path = from_upper_path_buf;
        } else {
            // Source is already in upper layer
            fprintf(stderr, "    -> Source in UPPER, creating hard link\n");
            from_link_path = from_real_path;
        }

        // Create the hard link in upper layer
        res = link(from_link_path, to_upper_path);
        if (res == -1) {
            fprintf(stderr, "    -> Failed to create hard link: %s\n", strerror(errno));
            return -errno;
        }

        // If there's a whiteout marker for 'to', remove it
        remove_whiteout_marker(overlay.upper_dir, to);

        fprintf(stderr, "    -> Hard link created successfully\n");
        return 0;
    }

    // Non-overlay path: use standard link
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
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "FSETATTR_X")) {
        return -ENOTSUP;
    }

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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "SETATTR_X")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** SETATTR_X OVERLAY: %s ***\n", path);

        // Find the file location in overlay
        char upper_path_buf[PATH_MAX], lower_path_buf[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path_buf, lower_path_buf);

        const char *target_path;
        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File does not exist\n");
                return -ENOENT;

            case OVERLAY_LOWER:
                // Copy from lower to upper first (OverlayFS semantics)
                fprintf(stderr, "    -> File in LOWER, copying to UPPER before setattr\n");
                res = copy_file_to_upper(lower_path_buf, upper_path_buf);
                if (res < 0) {
                    fprintf(stderr, "    -> Failed to copy file to upper: %d\n", res);
                    return res;
                }
                target_path = upper_path_buf;
                break;

            case OVERLAY_UPPER:
                // File already in upper layer
                fprintf(stderr, "    -> File in UPPER, applying setattr directly\n");
                target_path = upper_path_buf;
                break;
        }

        // Now apply all setattr operations to the upper layer file
        if (SETATTR_WANTS_MODE(attr)) {
            res = lchmod(target_path, attr->mode);
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
            res = lchown(target_path, uid, gid);
            if (res == -1) {
                return -errno;
            }
        }

        if (SETATTR_WANTS_SIZE(attr)) {
            res = truncate(target_path, attr->size);
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
            res = lutimes(target_path, tv);
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

            res = setattrlist(target_path, &attributes, &attr->crtime,
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

            res = setattrlist(target_path, &attributes, &attr->chgtime,
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

            res = setattrlist(target_path, &attributes, &attr->bkuptime,
                              sizeof(struct timespec), FSOPT_NOFOLLOW);

            if (res == -1) {
                return -errno;
            }
        }

        if (SETATTR_WANTS_FLAGS(attr)) {
            res = lchflags(target_path, attr->flags);
            if (res == -1) {
                return -errno;
            }
        }

        fprintf(stderr, "    -> Setattr completed successfully\n");
        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    if (SETATTR_WANTS_MODE(attr)) {
        res = lchmod(redirected, attr->mode);
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
        res = lchown(redirected, uid, gid);
        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_SIZE(attr)) {
        res = truncate(redirected, attr->size);
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
        res = lutimes(redirected, tv);
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

        res = setattrlist(redirected, &attributes, &attr->crtime,
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

        res = setattrlist(redirected, &attributes, &attr->chgtime,
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

        res = setattrlist(redirected, &attributes, &attr->bkuptime,
                          sizeof(struct timespec), FSOPT_NOFOLLOW);

        if (res == -1) {
            return -errno;
        }
    }

    if (SETATTR_WANTS_FLAGS(attr)) {
        res = lchflags(redirected, attr->flags);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "GETXTIMES")) {
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

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** GETXTIMES OVERLAY: %s ***\n", path);

        // Find the file location in overlay
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        const char *target_path;
        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                fprintf(stderr, "    -> Reading xtimes from UPPER: %s\n", upper_path);
                target_path = upper_path;
                break;

            case OVERLAY_LOWER:
                fprintf(stderr, "    -> Reading xtimes from LOWER: %s\n", lower_path);
                target_path = lower_path;
                break;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File not found\n");
                return -ENOENT;
        }

        attributes.commonattr = ATTR_CMN_BKUPTIME;
        res = getattrlist(target_path, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
        if (res == 0) {
            (void)memcpy(bkuptime, &(buf.xtime), sizeof(struct timespec));
        } else {
            (void)memset(bkuptime, 0, sizeof(struct timespec));
        }

        attributes.commonattr = ATTR_CMN_CRTIME;
        res = getattrlist(target_path, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
        if (res == 0) {
            (void)memcpy(crtime, &(buf.xtime), sizeof(struct timespec));
        } else {
            (void)memset(crtime, 0, sizeof(struct timespec));
        }

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    attributes.commonattr = ATTR_CMN_BKUPTIME;
    res = getattrlist(redirected, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
    if (res == 0) {
        (void)memcpy(bkuptime, &(buf.xtime), sizeof(struct timespec));
    } else {
        (void)memset(bkuptime, 0, sizeof(struct timespec));
    }

    attributes.commonattr = ATTR_CMN_CRTIME;
    res = getattrlist(redirected, &attributes, &buf, sizeof(buf), FSOPT_NOFOLLOW);
    if (res == 0) {
        (void)memcpy(crtime, &(buf.xtime), sizeof(struct timespec));
    } else {
        (void)memset(crtime, 0, sizeof(struct timespec));
    }

    return 0;
}

// Helper function to copy a file from lower layer to upper layer (copy-on-write)
static int copy_file_to_upper(const char* lower_path, const char* upper_path) {
    fprintf(stderr, "    Copy-on-write: copying %s -> %s\n", lower_path, upper_path);

    // Open source file (lower layer)
    int src_fd = open(lower_path, O_RDONLY);
    if (src_fd < 0) {
        fprintf(stderr, "    Failed to open source file: %s\n", strerror(errno));
        return -errno;
    }

    // Get source file metadata
    struct stat st;
    if (fstat(src_fd, &st) < 0) {
        close(src_fd);
        return -errno;
    }

    // Create parent directories in upper layer if needed
    create_parent_directories(upper_path);

    // Create destination file (upper layer)
    int dst_fd = open(upper_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (dst_fd < 0) {
        fprintf(stderr, "    Failed to create destination file: %s\n", strerror(errno));
        close(src_fd);
        return -errno;
    }

    // Copy data
    char buffer[65536];
    ssize_t bytes_read, bytes_written;
    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        bytes_written = write(dst_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            fprintf(stderr, "    Copy failed during write: %s\n", strerror(errno));
            close(src_fd);
            close(dst_fd);
            unlink(upper_path);  // Clean up partial copy
            return -EIO;
        }
    }

    if (bytes_read < 0) {
        fprintf(stderr, "    Copy failed during read: %s\n", strerror(errno));
        close(src_fd);
        close(dst_fd);
        unlink(upper_path);
        return -errno;
    }

    // Preserve ownership from source file (OverlayFS semantics)
    if (fchown(dst_fd, st.st_uid, st.st_gid) == -1) {
        fprintf(stderr, "    Warning: Failed to preserve ownership: %s\n", strerror(errno));
    }

    // Preserve timestamps
    struct timeval times[2];
    times[0].tv_sec = st.st_atimespec.tv_sec;
    times[0].tv_usec = st.st_atimespec.tv_nsec / 1000;
    times[1].tv_sec = st.st_mtimespec.tv_sec;
    times[1].tv_usec = st.st_mtimespec.tv_nsec / 1000;
    futimes(dst_fd, times);

    close(src_fd);
    close(dst_fd);

    fprintf(stderr, "    Copy-on-write completed successfully\n");
    return 0;
}

static int
loopback_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "CREATE")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** CREATE OVERLAY: %s ***\n", path);

        // New files are always created in upper layer (write operation)
        char upper_path[PATH_MAX];
        concatenate_path(path, overlay.upper_dir, upper_path);

        fprintf(stderr, "    -> Creating file in UPPER: %s\n", upper_path);

        // Create parent directories in upper layer if needed
        create_parent_directories(upper_path);

        // Create the file in upper layer
        fd = open(upper_path, fi->flags, mode);
        if (fd == -1) {
            fprintf(stderr, "    -> Failed to create file: %s\n", strerror(errno));
            return -errno;
        }

        // Set proper ownership to the calling user
        if (context && fchown(fd, context->uid, context->gid) == -1) {
            fprintf(stderr, "    Warning: Failed to set ownership for %s: %s\n", upper_path, strerror(errno));
        }

        // If there's a whiteout marker, remove it since we're creating a real file
        remove_whiteout_marker(overlay.upper_dir, path);

        fi->fh = fd;
        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    fd = open(redirected, fi->flags, mode);
    if (fd == -1) {
        return -errno;
    }

    // Set proper ownership to the calling user
    if (context && fchown(fd, context->uid, context->gid) == -1) {
        fprintf(stderr, "Warning: Failed to set ownership for %s: %s\n", redirected, strerror(errno));
    }

    fi->fh = fd;
    return 0;
}

static int
loopback_open(const char *path, struct fuse_file_info *fi)
{
    int fd;
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "OPEN")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found && strlen(overlay.upper_dir) > 0) {
        // Check if file needs write access
        bool needs_write = (fi->flags & (O_WRONLY | O_RDWR | O_APPEND | O_TRUNC)) != 0;

        // Find where the file currently exists
        char upper_path_buf[PATH_MAX], lower_path_buf[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path_buf, lower_path_buf);

        switch (location) {
            case OVERLAY_WHITEOUT:
                // File is deleted
                fprintf(stderr, "*** OPEN: %s is whiteout (deleted) ***\n", path);
                return -ENOENT;

            case OVERLAY_LOWER:
                if (needs_write) {
                    // File exists only in lower layer and we're opening for write
                    // Need to copy it to upper layer first (copy-on-write)
                    fprintf(stderr, "*** OPEN COPY-ON-WRITE: %s in lower, copying to upper %s ***\n",
                            path, upper_path_buf);

                    int res = copy_file_to_upper(lower_path_buf, upper_path_buf);
                    if (res < 0) {
                        return res;
                    }

                    // Now open the upper layer copy
                    fd = open(upper_path_buf, fi->flags);
                    if (fd == -1) {
                        return -errno;
                    }

                    fi->fh = fd;
                    return 0;
                } else {
                    // Read-only access - open from lower layer
                    fprintf(stderr, "*** OPEN READ: %s from LOWER: %s ***\n", path, lower_path_buf);
                    fd = open(lower_path_buf, fi->flags);
                    if (fd == -1) {
                        return -errno;
                    }

                    fi->fh = fd;
                    return 0;
                }

            case OVERLAY_UPPER:
                // File in upper layer
                fprintf(stderr, "*** OPEN: %s from UPPER: %s ***\n", path, upper_path_buf);
                fd = open(upper_path_buf, fi->flags);
                if (fd == -1) {
                    return -errno;
                }

                fi->fh = fd;
                return 0;

            case OVERLAY_NONE:
                // File doesn't exist
                fprintf(stderr, "*** OPEN: %s not found in overlay ***\n", path);
                return -ENOENT;
        }
    }

    // Fall back to regular open logic (no overlay or read-only access)
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    fd = open(redirected, fi->flags);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "SETXATTR")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** SETXATTR OVERLAY: %s (name=%s) ***\n", path, name);

        // Find the file location in overlay
        char upper_path_buf[PATH_MAX], lower_path_buf[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path_buf, lower_path_buf);

        const char *target_path;
        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File does not exist\n");
                return -ENOENT;

            case OVERLAY_LOWER:
                // File is in lower layer - copy it up first (OverlayFS semantics)
                fprintf(stderr, "    -> File in LOWER, copying to UPPER before setxattr\n");
                res = copy_file_to_upper(lower_path_buf, upper_path_buf);
                if (res < 0) {
                    fprintf(stderr, "    -> Failed to copy file to upper: %d\n", res);
                    return res;
                }
                target_path = upper_path_buf;
                break;

            case OVERLAY_UPPER:
                // File already in upper layer
                fprintf(stderr, "    -> Setting xattr on UPPER: %s\n", upper_path_buf);
                target_path = upper_path_buf;
                break;
        }

        flags |= XATTR_NOFOLLOW;
        if (strncmp(name, "com.apple.", 10) == 0) {
            char new_name[MAXPATHLEN] = "org.apple.";
            strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);
            res = setxattr(target_path, new_name, value, size, position, flags);
        } else {
            res = setxattr(target_path, name, value, size, position, flags);
        }

        if (res == -1) {
            return -errno;
        }

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    flags |= XATTR_NOFOLLOW;
    if (strncmp(name, "com.apple.", 10) == 0) {
        char new_name[MAXPATHLEN] = "org.apple.";
        strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);

        res = setxattr(redirected, new_name, value, size, position, flags);
    } else {
        res = setxattr(redirected, name, value, size, position, flags);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "GETXATTR")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** GETXATTR OVERLAY: %s (name=%s) ***\n", path, name);

        // Find the file location in overlay
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        const char *target_path;
        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                fprintf(stderr, "    -> Reading xattr from UPPER: %s\n", upper_path);
                target_path = upper_path;
                break;

            case OVERLAY_LOWER:
                fprintf(stderr, "    -> Reading xattr from LOWER: %s\n", lower_path);
                target_path = lower_path;
                break;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File not found\n");
                return -ENOENT;
        }

        if (strncmp(name, "com.apple.", 10) == 0) {
            char new_name[MAXPATHLEN] = "org.apple.";
            strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);
            res = getxattr(target_path, new_name, value, size, position, XATTR_NOFOLLOW);
        } else {
            res = getxattr(target_path, name, value, size, position, XATTR_NOFOLLOW);
        }

        if (res == -1) {
            return -errno;
        }

        return res;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    if (strncmp(name, "com.apple.", 10) == 0) {
        char new_name[MAXPATHLEN] = "org.apple.";
        strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);

        res = getxattr(redirected, new_name, value, size, position, XATTR_NOFOLLOW);
    } else {
        res = getxattr(redirected, name, value, size, position, XATTR_NOFOLLOW);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "LISTXATTR")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** LISTXATTR OVERLAY: %s ***\n", path);

        // Find the file location in overlay
        char upper_path[PATH_MAX], lower_path[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path, lower_path);

        const char *target_path;
        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_UPPER:
                fprintf(stderr, "    -> Listing xattr from UPPER: %s\n", upper_path);
                target_path = upper_path;
                break;

            case OVERLAY_LOWER:
                fprintf(stderr, "    -> Listing xattr from LOWER: %s\n", lower_path);
                target_path = lower_path;
                break;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File not found\n");
                return -ENOENT;
        }

        ssize_t res = listxattr(target_path, list, size, XATTR_NOFOLLOW);
        if (res > 0) {
            if (list) {
                size_t len = 0;
                char *curr = list;
                do {
                    size_t thislen = strlen(curr) + 1;
                    if (strncmp(curr, "org.apple.", 10) == 0) {
                        curr[0] = 'c';
                        curr[1] = 'o';
                        curr[2] = 'm';
                    }
                    curr += thislen;
                    len += thislen;
                } while (len < res);
            }
        }

        if (res == -1) {
            return -errno;
        }

        return res;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    ssize_t res = listxattr(redirected, list, size, XATTR_NOFOLLOW);
    if (res > 0) {
        if (list) {
            size_t len = 0;
            char *curr = list;
            do {
                size_t thislen = strlen(curr) + 1;
                if (strncmp(curr, "org.apple.", 10) == 0) {
                    curr[0] = 'c';
                    curr[1] = 'o';
                    curr[2] = 'm';
                }
                curr += thislen;
                len += thislen;
            } while (len < res);
        } else {
            /*
            ssize_t res2 = getxattr(redirected, G_KAUTH_FILESEC_XATTR, NULL, 0, 0,
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "REMOVEXATTR")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** REMOVEXATTR OVERLAY: %s (name=%s) ***\n", path, name);

        // Find the file location in overlay
        char upper_path_buf[PATH_MAX], lower_path_buf[PATH_MAX];
        overlay_location_t location = find_overlay_file_location(path, &overlay, upper_path_buf, lower_path_buf);

        const char *target_path;
        switch (location) {
            case OVERLAY_WHITEOUT:
                fprintf(stderr, "    -> File is whiteout (deleted)\n");
                return -ENOENT;

            case OVERLAY_NONE:
                fprintf(stderr, "    -> File does not exist\n");
                return -ENOENT;

            case OVERLAY_LOWER:
                // File is in lower layer - copy it up first (OverlayFS semantics)
                fprintf(stderr, "    -> File in LOWER, copying to UPPER before removexattr\n");
                res = copy_file_to_upper(lower_path_buf, upper_path_buf);
                if (res < 0) {
                    fprintf(stderr, "    -> Failed to copy file to upper: %d\n", res);
                    return res;
                }
                target_path = upper_path_buf;
                break;

            case OVERLAY_UPPER:
                // File already in upper layer
                fprintf(stderr, "    -> Removing xattr from UPPER: %s\n", upper_path_buf);
                target_path = upper_path_buf;
                break;
        }

        if (strncmp(name, "com.apple.", 10) == 0) {
            char new_name[MAXPATHLEN] = "org.apple.";
            strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);
            res = removexattr(target_path, new_name, XATTR_NOFOLLOW);
        } else {
            res = removexattr(target_path, name, XATTR_NOFOLLOW);
        }

        if (res == -1) {
            return -errno;
        }

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    if (strncmp(name, "com.apple.", 10) == 0) {
        char new_name[MAXPATHLEN] = "org.apple.";
        strncpy(new_name + 10, name + 10, sizeof(new_name) - 10);

        res = removexattr(redirected, new_name, XATTR_NOFOLLOW);
    } else {
        res = removexattr(redirected, name, XATTR_NOFOLLOW);
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
    struct fuse_context *context = fuse_get_context();

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "FALLOCATE")) {
        return -ENOTSUP;
    }

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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "STATFS")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** STATFS OVERLAY: %s ***\n", path);

        // For overlay filesystem, report statistics from upper layer
        // (where writes go - this is the limiting factor for space)
        fprintf(stderr, "    -> Getting filesystem stats from UPPER: %s\n", overlay.upper_dir);

        res = statfs(overlay.upper_dir, stbuf);
        if (res == -1) {
            return -errno;
        }

        stbuf->f_blocks = stbuf->f_blocks * stbuf->f_bsize / loopback.blocksize;
        stbuf->f_bavail = stbuf->f_bavail * stbuf->f_bsize / loopback.blocksize;
        stbuf->f_bfree = stbuf->f_bfree * stbuf->f_bsize / loopback.blocksize;
        stbuf->f_bsize = loopback.blocksize;

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected[PATH_MAX];
    get_passthrough_path(path, redirected);

    res = statfs(redirected, stbuf);
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

    // Check if we should block fseventsd
    if (should_block_fseventsd(context, "RENAMEX")) {
        return -ENOTSUP;
    }

    // Check if this is an overlay filesystem operation
    struct overlay_info overlay = find_overlay_in_tree(context->pid);
    if (overlay.found) {
        fprintf(stderr, "*** RENAMEX OVERLAY: %s -> %s (flags=0x%x) ***\n", path1, path2, flags);

        // Find locations of source and destination
        char path1_upper[PATH_MAX], path1_lower[PATH_MAX];
        char path2_upper[PATH_MAX], path2_lower[PATH_MAX];
        overlay_location_t loc1 = find_overlay_file_location(path1, &overlay, path1_upper, path1_lower);
        overlay_location_t loc2 = find_overlay_file_location(path2, &overlay, path2_upper, path2_lower);

        // Check if source exists
        if (loc1 == OVERLAY_WHITEOUT || loc1 == OVERLAY_NONE) {
            fprintf(stderr, "    -> Source file does not exist\n");
            return -ENOENT;
        }

        // Handle RENAME_SWAP flag (similar to exchange)
        if (flags & RENAME_SWAP) {
            fprintf(stderr, "    -> RENAME_SWAP requested\n");

            // Check if both files exist
            if (loc2 == OVERLAY_WHITEOUT || loc2 == OVERLAY_NONE) {
                fprintf(stderr, "    -> Destination does not exist (required for SWAP)\n");
                return -ENOENT;
            }

            // Copy up both files if needed
            if (loc1 == OVERLAY_LOWER) {
                fprintf(stderr, "    -> Copying up path1 from LOWER to UPPER\n");
                create_parent_directories(path1_upper);
                if (copy_file_to_upper(path1_lower, path1_upper) != 0) {
                    return -EIO;
                }
            }
            if (loc2 == OVERLAY_LOWER) {
                fprintf(stderr, "    -> Copying up path2 from LOWER to UPPER\n");
                create_parent_directories(path2_upper);
                if (copy_file_to_upper(path2_lower, path2_upper) != 0) {
                    return -EIO;
                }
            }

            // Perform swap in upper layer
            res = renamex_np(path1_upper, path2_upper, flags);
            if (res == -1) {
                fprintf(stderr, "    -> Swap failed: %s\n", strerror(errno));
                return -errno;
            }

            return 0;
        }

        // Handle normal rename (possibly with RENAME_EXCL flag)
        if (loc1 == OVERLAY_LOWER) {
            fprintf(stderr, "    -> Source is in LOWER, copying to UPPER at new location\n");
            create_parent_directories(path2_upper);
            if (copy_file_to_upper(path1_lower, path2_upper) != 0) {
                return -EIO;
            }

            // Create whiteout marker at old location
            create_whiteout_marker(path1, &overlay);
        } else {
            // Source is in upper - perform normal rename
            fprintf(stderr, "    -> Source is in UPPER, renaming\n");
            create_parent_directories(path2_upper);
            res = renamex_np(path1_upper, path2_upper, flags);
            if (res == -1) {
                fprintf(stderr, "    -> Rename failed: %s\n", strerror(errno));
                return -errno;
            }
        }

        // Remove any whiteout marker at destination
        remove_whiteout_marker(overlay.upper_dir, path2);

        return 0;
    }

    // Non-overlay path: use passthrough
    char redirected_path1[PATH_MAX];
    char redirected_path2[PATH_MAX];
    get_passthrough_path(path1, redirected_path1);
    get_passthrough_path(path2, redirected_path2);

    res = renamex_np(redirected_path1, redirected_path2, flags);
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

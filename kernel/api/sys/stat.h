#pragma once

#include <common/stdint.h>

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFREG 0100000
#define S_IFIFO 0010000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000

#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IREAD S_IRUSR
#define S_IWRITE S_IWUSR
#define S_IEXEC S_IXUSR
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)

#define S_IRGRP (S_IRUSR >> 3)
#define S_IWGRP (S_IWUSR >> 3)
#define S_IXGRP (S_IXUSR >> 3)
#define S_IRWXG (S_IRWXU >> 3)

#define S_IROTH (S_IRGRP >> 3)
#define S_IWOTH (S_IWGRP >> 3)
#define S_IXOTH (S_IXGRP >> 3)
#define S_IRWXO (S_IRWXG >> 3)

#define ACCESSPERMS (S_IRWXU | S_IRWXG | S_IRWXO)
#define ALLPERMS (ACCESSPERMS | S_ISUID | S_ISGID | S_ISVTX)

struct linux_stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned short st_mode;
    unsigned short st_nlink;
    unsigned short st_uid;
    unsigned short st_gid;
    unsigned long st_rdev;
    unsigned long st_size;
    unsigned long st_blksize;
    unsigned long st_blocks;
    unsigned long st_atime;
    unsigned long st_atime_nsec;
    unsigned long st_mtime;
    unsigned long st_mtime_nsec;
    unsigned long st_ctime;
    unsigned long st_ctime_nsec;
    unsigned long __unused4;
    unsigned long __unused5;
};

struct linux_stat64 {
    unsigned long long st_dev;
    unsigned char __pad0[4];

    unsigned long __st_ino;

    unsigned int st_mode;
    unsigned int st_nlink;

    unsigned long st_uid;
    unsigned long st_gid;

    unsigned long long st_rdev;
    unsigned char __pad3[4];

    long long st_size;
    unsigned long st_blksize;

    /* Number 512-byte blocks allocated. */
    unsigned long long st_blocks;

    unsigned long st_atime;
    unsigned long st_atime_nsec;

    unsigned long st_mtime;
    unsigned int st_mtime_nsec;

    unsigned long st_ctime;
    unsigned long st_ctime_nsec;

    unsigned long long st_ino;
};

struct linux_old_stat {
    unsigned short st_dev;
    unsigned short st_ino;
    unsigned short st_mode;
    unsigned short st_nlink;
    unsigned short st_uid;
    unsigned short st_gid;
    unsigned short st_rdev;
    unsigned long st_size;
    unsigned long st_atime;
    unsigned long st_mtime;
    unsigned long st_ctime;
};

struct statx_timestamp {
    int64_t tv_sec;   // Seconds since the Epoch (UNIX time)
    uint32_t tv_nsec; // Nanoseconds since tv_sec
    uint32_t __reserved;
};

struct statx {
    uint32_t stx_mask;       // Mask of bits indicating filled fields
    uint32_t stx_blksize;    // Block size for filesystem I/O
    uint64_t stx_attributes; // Extra file attribute indicators
    uint32_t stx_nlink;      // Number of hard links
    uint32_t stx_uid;        // User ID of owner
    uint32_t stx_gid;        // Group ID of owner
    uint16_t stx_mode;       // File type and mode
    uint16_t __spare0[1];
    uint64_t stx_ino;    // Inode number
    uint64_t stx_size;   // Total size in bytes
    uint64_t stx_blocks; // Number of 512B blocks allocated
    // Mask to show what's supported in stx_attributes
    uint64_t stx_attributes_mask;

    // The following fields are file timestamps
    struct statx_timestamp stx_atime; // Last access
    struct statx_timestamp stx_btime; // Creation
    struct statx_timestamp stx_ctime; // Last status change
    struct statx_timestamp stx_mtime; // Last modification

    // If this file represents a device, then the next two fields contain
    // the ID of the device
    uint32_t stx_rdev_major; // Major ID
    uint32_t stx_rdev_minor; // Minor ID

    // The next two fields contain the ID of the device
    // containing the filesystem where the file resides
    uint32_t stx_dev_major; // Major ID
    uint32_t stx_dev_minor; // Minor ID

    uint64_t stx_mnt_id; // Mount ID

    // Direct I/O alignment restrictions
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;

    uint64_t stx_subvol; // Subvolume identifier

    uint32_t stx_atomic_write_unit_min;     // Min atomic write unit in bytes
    uint32_t stx_atomic_write_unit_max;     // Max atomic write unit in bytes
    uint32_t stx_atomic_write_segments_max; // Max atomic write segment count

    // File offset alignment for direct I/O reads
    uint32_t stx_dio_read_offset_align;

    // Optimised max atomic write unit in bytes
    uint32_t stx_atomic_write_unit_max_opt;
    uint32_t __spare2[1];

    uint64_t __spare3[8];
};

#define STATX_TYPE 0x00000001U           // Want/got stx_mode & S_IFMT
#define STATX_MODE 0x00000002U           // Want/got stx_mode & ~S_IFMT
#define STATX_NLINK 0x00000004U          // Want/got stx_nlink
#define STATX_UID 0x00000008U            // Want/got stx_uid
#define STATX_GID 0x00000010U            // Want/got stx_gid
#define STATX_ATIME 0x00000020U          // Want/got stx_atime
#define STATX_MTIME 0x00000040U          // Want/got stx_mtime
#define STATX_CTIME 0x00000080U          // Want/got stx_ctime
#define STATX_INO 0x00000100U            // Want/got stx_ino
#define STATX_SIZE 0x00000200U           // Want/got stx_size
#define STATX_BLOCKS 0x00000400U         // Want/got stx_blocks
#define STATX_BASIC_STATS 0x000007ffU    // The stuff in the normal stat struct
#define STATX_BTIME 0x00000800U          // Want/got stx_btime
#define STATX_MNT_ID 0x00001000U         // Got stx_mnt_id
#define STATX_DIOALIGN 0x00002000U       // Want/got direct I/O alignment info
#define STATX_MNT_ID_UNIQUE 0x00004000U  // Want/got extended stx_mount_id
#define STATX_SUBVOL 0x00008000U         // Want/got stx_subvol
#define STATX_WRITE_ATOMIC 0x00010000U   // Want/got atomic_write_* fields
#define STATX_DIO_READ_ALIGN 0x00020000U // Want/got dio read alignment info

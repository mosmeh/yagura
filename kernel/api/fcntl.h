#pragma once

// Duplicate file descriptor.
#define F_DUPFD 0

// Duplicate file descriptor with close-on-exit set.
#define F_DUPFD_CLOEXEC 1030

// Get file descriptor flags.
#define F_GETFD 1

// Set file descriptor flags.
#define F_SETFD 2

// Get file status flags.
#define F_GETFL 3

// Set file status flags.
#define F_SETFL 4

#define O_ACCMODE 00000003
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100
#define O_EXCL 00000200
#define O_TRUNC 00001000
#define O_NONBLOCK 00004000
#define O_NOFOLLOW 00400000 // Do not follow links.
#define O_CLOEXEC 02000000  // Set close_on_exec.

#define FD_CLOEXEC 1

// Special value used to indicate the *at functions should use the current
// working directory.
#define AT_FDCWD -100

#define AT_SYMLINK_NOFOLLOW 0x100 // Do not follow symbolic links.
#define AT_REMOVEDIR 0x200        // Remove directory instead of unlinking file.
#define AT_SYMLINK_FOLLOW 0x400   // Follow symbolic links.
#define AT_EMPTY_PATH 0x1000      // Allow empty relative pathname.

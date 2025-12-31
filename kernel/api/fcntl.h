#pragma once

#define F_DUPFD 0
#define F_GETFL 3
#define F_SETFL 4

#define O_ACCMODE 00000003
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_CREAT 00000100
#define O_EXCL 00000200
#define O_TRUNC 00001000
#define O_NONBLOCK 00004000
#define O_NOFOLLOW 00400000

// Special value used to indicate the *at functions should use the current
// working directory.
#define AT_FDCWD -100

#define AT_SYMLINK_NOFOLLOW 0x100 // Do not follow symbolic links.
#define AT_REMOVEDIR 0x200        // Remove directory instead of unlinking file.
#define AT_SYMLINK_FOLLOW 0x400   // Follow symbolic links.
#define AT_EMPTY_PATH 0x1000      // Allow empty relative pathname.

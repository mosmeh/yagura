#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* strdup(const char* src) {
    size_t len = strlen(src);
    char* buf = malloc((len + 1) * sizeof(char));
    if (!buf)
        return NULL;

    memcpy(buf, src, len);
    buf[len] = '\0';
    return buf;
}

#define ENUMERATE_ERRORS(F)                                                    \
    F(EPERM, "Operation not permitted")                                        \
    F(ENOENT, "No such file or directory")                                     \
    F(ESRCH, "No such process")                                                \
    F(EINTR, "Interrupted system call")                                        \
    F(EIO, "Input/output error")                                               \
    F(ENXIO, "No such device or address")                                      \
    F(E2BIG, "Argument list too long")                                         \
    F(ENOEXEC, "Exec format error")                                            \
    F(EBADF, "Bad file descriptor")                                            \
    F(ECHILD, "No child processes")                                            \
    F(EAGAIN, "Resource temporarily unavailable")                              \
    F(ENOMEM, "Cannot allocate memory")                                        \
    F(EACCES, "Permission denied")                                             \
    F(EFAULT, "Bad address")                                                   \
    F(ENOTBLK, "Block device required")                                        \
    F(EBUSY, "Device or resource busy")                                        \
    F(EEXIST, "File exists")                                                   \
    F(EXDEV, "Invalid cross-device link")                                      \
    F(ENODEV, "No such device")                                                \
    F(ENOTDIR, "Not a directory")                                              \
    F(EISDIR, "Is a directory")                                                \
    F(EINVAL, "Invalid argument")                                              \
    F(ENFILE, "Too many open files in system")                                 \
    F(EMFILE, "Too many open files")                                           \
    F(ENOTTY, "Inappropriate ioctl for device")                                \
    F(ETXTBSY, "Text file busy")                                               \
    F(EFBIG, "File too large")                                                 \
    F(ENOSPC, "No space left on device")                                       \
    F(ESPIPE, "Illegal seek")                                                  \
    F(EROFS, "Read-only file system")                                          \
    F(EMLINK, "Too many links")                                                \
    F(EPIPE, "Broken pipe")                                                    \
    F(EDOM, "Numerical argument out of domain")                                \
    F(ERANGE, "Numerical result out of range")                                 \
    F(EDEADLK, "Resource deadlock avoided")                                    \
    F(ENAMETOOLONG, "File name too long")                                      \
    F(ENOLCK, "No locks available")                                            \
    F(ENOSYS, "Function not implemented")                                      \
    F(ENOTEMPTY, "Directory not empty")                                        \
    F(ELOOP, "Too many levels of symbolic links")                              \
    F(ENOMSG, "No message of desired type")                                    \
    F(EIDRM, "Identifier removed")                                             \
    F(ECHRNG, "Channel number out of range")                                   \
    F(EL2NSYNC, "Level 2 not synchronized")                                    \
    F(EL3HLT, "Level 3 halted")                                                \
    F(EL3RST, "Level 3 reset")                                                 \
    F(ELNRNG, "Link number out of range")                                      \
    F(EUNATCH, "Protocol driver not attached")                                 \
    F(ENOCSI, "No CSI structure available")                                    \
    F(EL2HLT, "Level 2 halted")                                                \
    F(EBADE, "Invalid exchange")                                               \
    F(EBADR, "Invalid request descriptor")                                     \
    F(EXFULL, "Exchange full")                                                 \
    F(ENOANO, "No anode")                                                      \
    F(EBADRQC, "Invalid request code")                                         \
    F(EBADSLT, "Invalid slot")                                                 \
    F(EBFONT, "Bad font file format")                                          \
    F(ENOSTR, "Device not a stream")                                           \
    F(ENODATA, "No data available")                                            \
    F(ETIME, "Timer expired")                                                  \
    F(ENOSR, "Out of streams resources")                                       \
    F(ENONET, "Machine is not on the network")                                 \
    F(ENOPKG, "Package not installed")                                         \
    F(EREMOTE, "Object is remote")                                             \
    F(ENOLINK, "Link has been severed")                                        \
    F(EADV, "Advertise error")                                                 \
    F(ESRMNT, "Srmount error")                                                 \
    F(ECOMM, "Communication error on send")                                    \
    F(EPROTO, "Protocol error")                                                \
    F(EMULTIHOP, "Multihop attempted")                                         \
    F(EDOTDOT, "RFS specific error")                                           \
    F(EBADMSG, "Bad message")                                                  \
    F(EOVERFLOW, "Value too large for defined data type")                      \
    F(ENOTUNIQ, "Name not unique on network")                                  \
    F(EBADFD, "File descriptor in bad state")                                  \
    F(EREMCHG, "Remote address changed")                                       \
    F(ELIBACC, "Can not access a needed shared library")                       \
    F(ELIBBAD, "Accessing a corrupted shared library")                         \
    F(ELIBSCN, ".lib section in a.out corrupted")                              \
    F(ELIBMAX, "Attempting to link in too many shared libraries")              \
    F(ELIBEXEC, "Cannot exec a shared library directly")                       \
    F(EILSEQ, "Invalid or incomplete multibyte or wide character")             \
    F(ERESTART, "Interrupted system call should be restarted")                 \
    F(ESTRPIPE, "Streams pipe error")                                          \
    F(EUSERS, "Too many users")                                                \
    F(ENOTSOCK, "Socket operation on non-socket")                              \
    F(EDESTADDRREQ, "Destination address required")                            \
    F(EMSGSIZE, "Message too long")                                            \
    F(EPROTOTYPE, "Protocol wrong type for socket")                            \
    F(ENOPROTOOPT, "Protocol not available")                                   \
    F(EPROTONOSUPPORT, "Protocol not supported")                               \
    F(ESOCKTNOSUPPORT, "Socket type not supported")                            \
    F(EOPNOTSUPP, "Operation not supported")                                   \
    F(EPFNOSUPPORT, "Protocol family not supported")                           \
    F(EAFNOSUPPORT, "Address family not supported by protocol")                \
    F(EADDRINUSE, "Address already in use")                                    \
    F(EADDRNOTAVAIL, "Cannot assign requested address")                        \
    F(ENETDOWN, "Network is down")                                             \
    F(ENETUNREACH, "Network is unreachable")                                   \
    F(ENETRESET, "Network dropped connection on reset")                        \
    F(ECONNABORTED, "Software caused connection abort")                        \
    F(ECONNRESET, "Connection reset by peer")                                  \
    F(ENOBUFS, "No buffer space available")                                    \
    F(EISCONN, "Transport endpoint is already connected")                      \
    F(ENOTCONN, "Transport endpoint is not connected")                         \
    F(ESHUTDOWN, "Cannot send after transport endpoint shutdown")              \
    F(ETOOMANYREFS, "Too many references: cannot splice")                      \
    F(ETIMEDOUT, "Connection timed out")                                       \
    F(ECONNREFUSED, "Connection refused")                                      \
    F(EHOSTDOWN, "Host is down")                                               \
    F(EHOSTUNREACH, "No route to host")                                        \
    F(EALREADY, "Operation already in progress")                               \
    F(EINPROGRESS, "Operation now in progress")                                \
    F(ESTALE, "Stale file handle")                                             \
    F(EUCLEAN, "Structure needs cleaning")                                     \
    F(ENOTNAM, "Not a XENIX named type file")                                  \
    F(ENAVAIL, "No XENIX semaphores available")                                \
    F(EISNAM, "Is a named type file")                                          \
    F(EREMOTEIO, "Remote I/O error")                                           \
    F(EDQUOT, "Disk quota exceeded")                                           \
    F(ENOMEDIUM, "No medium found")                                            \
    F(EMEDIUMTYPE, "Wrong medium type")                                        \
    F(ECANCELED, "Operation canceled")                                         \
    F(ENOKEY, "Required key not available")                                    \
    F(EKEYEXPIRED, "Key has expired")                                          \
    F(EKEYREVOKED, "Key has been revoked")                                     \
    F(EKEYREJECTED, "Key was rejected by service")                             \
    F(EOWNERDEAD, "Owner died")                                                \
    F(ENOTRECOVERABLE, "State not recoverable")                                \
    F(ERFKILL, "Operation not possible due to RF-kill")                        \
    F(EHWPOISON, "Memory page has hardware error")

static const char* const sys_errlist[] = {[0] = "Success",
#define F(name, msg) [name] = (msg),
                                          ENUMERATE_ERRORS(F)
#undef F
};

static const char* const sys_errname[] = {[0] = "0",
#define F(name, msg) [name] = #name,
                                          ENUMERATE_ERRORS(F)
#undef F
};

char* strerror(int errnum) {
    if (0 <= errnum && errnum <= EMAXERRNO && sys_errlist[errnum])
        return (char*)sys_errlist[errnum];
    return "Unknown error";
}

const char* strerrorname_np(int errnum) {
    if (0 <= errnum && errnum <= EMAXERRNO && sys_errname[errnum])
        return sys_errname[errnum];
    return NULL;
}

const char* strerrordesc_np(int errnum) { return strerror(errnum); }

#define NAME(name, msg) STRINGIFY(name),
#define MSG(name, msg) msg,
const char* const sys_signame[NSIG] = {ENUMERATE_SIGNALS(NAME)};
const char* const sys_siglist[NSIG] = {ENUMERATE_SIGNALS(MSG)};
#undef NAME
#undef MSG

static _Thread_local char buf[32];

char* strsignal(int signum) {
    const char* desc = NULL;
    if (0 <= signum && signum < NSIG)
        desc = sys_siglist[signum];
    if (desc)
        return (char*)desc;
    if (SIGRTMIN <= signum && signum <= SIGRTMAX)
        (void)snprintf(buf, sizeof(buf), "Real-time signal %d",
                       signum - SIGRTMIN);
    else
        (void)snprintf(buf, sizeof(buf), "Unknown signal %d", signum);
    return buf;
}

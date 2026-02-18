#include <errno.h>
#include <panic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(void) {
    char hostname[UTSNAME_LENGTH];
    memset(hostname, 'x', sizeof(hostname));
    ASSERT_OK(sethostname(hostname, UTSNAME_LENGTH - 1));

    char domainname[UTSNAME_LENGTH];
    memset(domainname, 'y', sizeof(domainname));
    ASSERT_OK(setdomainname(domainname, UTSNAME_LENGTH - 1));

    struct utsname buf;
    memset(buf.nodename, 0xff, sizeof(buf.nodename));
    memset(buf.domainname, 0xff, sizeof(buf.domainname));
    ASSERT_OK(uname(&buf));
    ASSERT(!memcmp(buf.nodename, hostname, UTSNAME_LENGTH - 1));
    ASSERT(buf.nodename[UTSNAME_LENGTH - 1] == 0);
    ASSERT(!memcmp(buf.domainname, domainname, UTSNAME_LENGTH - 1));
    ASSERT(buf.domainname[UTSNAME_LENGTH - 1] == 0);

    ASSERT_ERRNO(sethostname(hostname, UTSNAME_LENGTH), EINVAL);
    ASSERT_ERRNO(setdomainname(domainname, UTSNAME_LENGTH), EINVAL);
    ASSERT_ERRNO(sethostname(NULL, 1), EFAULT);
    ASSERT_ERRNO(setdomainname(NULL, 1), EFAULT);

    ASSERT_OK(sethostname(NULL, 0));
    ASSERT_OK(setdomainname(NULL, 0));

    memset(buf.nodename, 0xff, sizeof(buf.nodename));
    memset(buf.domainname, 0xff, sizeof(buf.domainname));
    ASSERT_OK(uname(&buf));
    for (size_t i = 0; i < sizeof(buf.nodename); ++i) {
        ASSERT(buf.nodename[i] == 0);
        ASSERT(buf.domainname[i] == 0);
    }

    return EXIT_SUCCESS;
}

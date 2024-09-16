#pragma once

#define UTSNAME_LENGTH 65

struct utsname {
    char sysname[UTSNAME_LENGTH];
    char nodename[UTSNAME_LENGTH];
    char release[UTSNAME_LENGTH];
    char version[UTSNAME_LENGTH];
    char machine[UTSNAME_LENGTH];
    char domainname[UTSNAME_LENGTH];
};

struct linux_oldold_utsname {
    char sysname[9];
    char nodename[9];
    char release[9];
    char version[9];
    char machine[9];
};

struct linux_old_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
};

#pragma once

// Set if VM shared between processes.
#define CLONE_VM 0x00000100

// Set if fs info shared between processes.
#define CLONE_FS 0x00000200

// Set if open files shared between processes.
#define CLONE_FILES 0x00000400

// Set if signal handlers and blocked signals shared
#define CLONE_SIGHAND 0x00000800

// Set to add to same thread group.
#define CLONE_THREAD 0x00010000

// Set TLS info.
#define CLONE_SETTLS 0x00080000

// Store TID in userlevel buffer before MM copy.
#define CLONE_PARENT_SETTID 0x00100000

// Register exit futex and memory location to clear.
#define CLONE_CHILD_CLEARTID 0x00200000

// Store TID in userlevel buffer in the child.
#define CLONE_CHILD_SETTID 0x01000000

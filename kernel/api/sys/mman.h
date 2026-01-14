#pragma once

#define PROT_NONE 0x0  // page can not be accessed
#define PROT_READ 0x1  // page can be read
#define PROT_WRITE 0x2 // page can be written
#define PROT_EXEC 0x4  // page can be executed

#define MAP_SHARED 0x1
#define MAP_PRIVATE 0x2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON MAP_ANONYMOUS

#define MAP_FAILED ((void*)-1)

#define MS_ASYNC 1      // Sync memory asynchronously.
#define MS_SYNC 4       // Synchronous memory sync.
#define MS_INVALIDATE 2 // Invalidate the caches.

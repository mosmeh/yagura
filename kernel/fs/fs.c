#include "private.h"
#include <kernel/fs/fs.h>

void fs_init(void) {
    file_init();
    path_init();
    filemap_init();
    vfs_init();
    pipe_init();
}

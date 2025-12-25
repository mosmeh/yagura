#pragma once

#include <kernel/resource.h>

struct path {
    // The inode associated with the path.
    // NULL if vfs_resolve_path was called with O_ALLOW_NOENT and
    // the last component of the path does not exist.
    struct inode* inode;

    // The basename of the path. NULL for the root path.
    char* basename;

    // The parent of the path. NULL for the root path.
    struct path* parent;
};

// Creates a path representing the root directory.
struct path* path_create_root(struct inode* root);

// Returns a string representation of the path.
// The string representation is an absolute path within the current chroot.
// The caller is responsible for kfree()ing the returned string.
char* path_to_string(const struct path*);

// Returns a clone of the path.
struct path* path_dup(const struct path*);

// Joins a path with a basename associated with an inode.
struct path* path_join(struct path* parent, struct inode* inode,
                       const char* basename);

// Destroys the last component of the path, but not the parents.
void path_destroy_last(struct path*);

// Destroys the path and all its parents.
void path_destroy_recursive(struct path*);

DEFINE_FREE(path, struct path*, path_destroy_recursive)

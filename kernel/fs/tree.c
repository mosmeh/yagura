#include "tree.h"
#include <common/string.h>
#include <kernel/api/dirent.h>
#include <kernel/api/err.h>
#include <string.h>

static tree_node* find_child_by_name(tree_node* node, const char* name) {
    tree_node* child = node->first_child;
    if (!child)
        return NULL;

    for (;;) {
        if (!strcmp(child->base_file.name, name))
            return child;

        if (!child->next_sibling)
            return NULL;

        child = child->next_sibling;
    }
}

void tree_node_append_child(tree_node* node, tree_node* new_child) {
    new_child->next_sibling = NULL;

    if (!node->first_child) {
        node->first_child = new_child;
        return;
    }

    tree_node* child = node->first_child;
    while (child->next_sibling)
        child = child->next_sibling;
    child->next_sibling = new_child;
}

struct file* tree_node_lookup(struct file* file, const char* name) {
    tree_node* node = (tree_node*)file;
    tree_node* child = find_child_by_name(node, name);
    if (!child)
        return ERR_PTR(-ENOENT);
    return &child->base_file;
}

long tree_node_readdir(file_description* desc, void* dirp, unsigned int count) {
    tree_node* node = (tree_node*)desc->file;
    tree_node* child = node->first_child;
    if (!child)
        return 0;

    for (off_t i = 0; i < desc->offset; ++i) {
        child = child->next_sibling;
        if (!child)
            return 0;
    }

    uintptr_t buf = (uintptr_t)dirp;
    long nread = 0;

    while (count > 0 && child) {
        struct file* file = &child->base_file;
        size_t name_len = strlen(file->name);
        size_t name_size = name_len + 1;
        size_t size = offsetof(struct dirent, d_name) + name_size;
        if (count < size)
            break;

        struct dirent* dent = (struct dirent*)buf;
        dent->d_type = mode_to_dirent_type(file->mode);
        dent->d_reclen = size;
        dent->d_namlen = name_len;
        strlcpy(dent->d_name, file->name, name_size);

        ++desc->offset;
        child = child->next_sibling;
        nread += size;
        buf += size;
        count -= size;
    }

    if (nread == 0)
        return -EINVAL;
    return nread;
}

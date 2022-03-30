#pragma once

#include "fs.h"

typedef struct tree_node {
    struct file base_file;
    struct tree_node* first_child;
    struct tree_node* next_sibling;
} tree_node;

struct file* tree_node_lookup(struct file* file, const char* name);
long tree_node_readdir(file_description* desc, void* dirp, unsigned int count);

void tree_node_append_child(tree_node* node, tree_node* new_child);

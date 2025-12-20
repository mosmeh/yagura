#pragma once

#include <common/panic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define COLOR_MASK ((uintptr_t)0x1)

struct tree {
    struct tree_node* root;
};

struct tree_node {
    uintptr_t parent_and_color; // The least significant bit is color
    struct tree_node* left;
    struct tree_node* right;
};

void tree_insert(struct tree*, struct tree_node* parent,
                 struct tree_node* node);
void tree_remove(struct tree*, struct tree_node*);

static inline bool tree_is_empty(const struct tree* tree) {
    return !tree->root;
}

static inline struct tree_node* tree_first(const struct tree* tree) {
    struct tree_node* node = tree->root;
    if (!node)
        return NULL;
    while (node->left)
        node = node->left;
    return node;
}

static inline struct tree_node* tree_last(const struct tree* tree) {
    struct tree_node* node = tree->root;
    if (!node)
        return NULL;
    while (node->right)
        node = node->right;
    return node;
}

static inline struct tree_node* tree_parent(const struct tree_node* node) {
    ASSERT(node);
    return (void*)(node->parent_and_color & ~COLOR_MASK);
}

static inline struct tree_node* tree_next(const struct tree_node* node) {
    ASSERT(node);
    if (node->right) {
        struct tree_node* child = node->right;
        while (child->left)
            child = child->left;
        return child;
    }
    struct tree_node* parent = tree_parent(node);
    while (parent && node == parent->right) {
        node = parent;
        parent = tree_parent(parent);
    }
    return parent;
}

static inline struct tree_node* tree_prev(const struct tree_node* node) {
    ASSERT(node);
    if (node->left) {
        struct tree_node* child = node->left;
        while (child->right)
            child = child->right;
        return child;
    }
    struct tree_node* parent = tree_parent(node);
    while (parent && node == parent->left) {
        node = parent;
        parent = tree_parent(parent);
    }
    return parent;
}

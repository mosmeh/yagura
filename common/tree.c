// Red-black tree implementation

#include "tree.h"

#define COLOR_RED 0
#define COLOR_BLACK 1

static uint8_t color(const struct tree_node* node) {
    ASSERT(node);
    return node->parent_and_color & COLOR_MASK;
}

static void set_parent_and_color(struct tree_node* node,
                                 struct tree_node* parent, uint8_t color) {
    ASSERT(node);
    ASSERT(!((uintptr_t)parent & COLOR_MASK));
    ASSERT(!(color & ~COLOR_MASK));
    node->parent_and_color = (uintptr_t)parent | color;
}

static void set_parent(struct tree_node* node, struct tree_node* parent) {
    set_parent_and_color(node, parent, color(node));
}

static void set_color(struct tree_node* node, uint8_t color) {
    set_parent_and_color(node, tree_parent(node), color);
}

static void replace_child(struct tree* tree, struct tree_node* parent,
                          struct tree_node* old_node,
                          struct tree_node* new_node) {
    if (!parent)
        tree->root = new_node;
    else if (parent->left == old_node)
        parent->left = new_node;
    else
        parent->right = new_node;
}

static void rotate_left(struct tree* tree, struct tree_node* node) {
    ASSERT(node);
    struct tree_node* pivot = node->right;
    ASSERT(pivot);
    struct tree_node* parent = tree_parent(node);

    node->right = pivot->left;
    if (node->right)
        set_parent(node->right, node);

    pivot->left = node;
    set_parent(node, pivot);

    set_parent(pivot, parent);
    replace_child(tree, parent, node, pivot);
}

static void rotate_right(struct tree* tree, struct tree_node* node) {
    ASSERT(node);
    struct tree_node* pivot = node->left;
    ASSERT(pivot);
    struct tree_node* parent = tree_parent(node);

    node->left = pivot->right;
    if (node->left)
        set_parent(node->left, node);

    pivot->right = node;
    set_parent(node, pivot);

    set_parent(pivot, parent);
    replace_child(tree, parent, node, pivot);
}

static void balance_after_insertion(struct tree* tree, struct tree_node* node) {
    while (tree_parent(node) && color(tree_parent(node)) == COLOR_RED) {
        struct tree_node* parent = tree_parent(node);
        struct tree_node* grandparent = tree_parent(parent);
        if (parent == grandparent->left) {
            struct tree_node* uncle = grandparent->right;
            if (uncle && color(uncle) == COLOR_RED) {
                set_color(parent, COLOR_BLACK);
                set_color(uncle, COLOR_BLACK);
                set_color(grandparent, COLOR_RED);
                node = grandparent;
            } else {
                if (node == parent->right) {
                    rotate_left(tree, parent);
                    node = parent;
                    parent = tree_parent(node);
                }
                set_color(parent, COLOR_BLACK);
                set_color(grandparent, COLOR_RED);
                rotate_right(tree, grandparent);
            }
        } else {
            struct tree_node* uncle = grandparent->left;
            if (uncle && color(uncle) == COLOR_RED) {
                set_color(parent, COLOR_BLACK);
                set_color(uncle, COLOR_BLACK);
                set_color(grandparent, COLOR_RED);
                node = grandparent;
            } else {
                if (node == parent->left) {
                    rotate_right(tree, parent);
                    node = parent;
                    parent = tree_parent(node);
                }
                set_color(parent, COLOR_BLACK);
                set_color(grandparent, COLOR_RED);
                rotate_left(tree, grandparent);
            }
        }
    }
    set_color(tree->root, COLOR_BLACK);
}

void tree_insert(struct tree* tree, struct tree_node* parent,
                 struct tree_node* node) {
    ASSERT(node);
    ASSERT(!node->parent_and_color);
    ASSERT(!node->left);
    ASSERT(!node->right);

    if (!parent) {
        ASSERT(tree->root == node);
        set_parent_and_color(node, NULL, COLOR_BLACK);
        return;
    }

    ASSERT(parent->left == node || parent->right == node);
    set_parent_and_color(node, parent, COLOR_RED);

    if (tree_parent(parent))
        balance_after_insertion(tree, node);
}

static void swap_node(struct tree_node** a, struct tree_node** b) {
    struct tree_node* tmp = *a;
    *a = *b;
    *b = tmp;
}

static void swap_parent(struct tree_node* a, struct tree_node* b) {
    struct tree_node* tmp = tree_parent(a);
    set_parent(a, tree_parent(b));
    set_parent(b, tmp);
}

static void swap_color(struct tree_node* a, struct tree_node* b) {
    uint8_t tmp = color(a);
    set_color(a, color(b));
    set_color(b, tmp);
}

static void balance_after_removal(struct tree* tree, struct tree_node* parent,
                                  struct tree_node* node) {
    while (node != tree->root && (!node || color(node) == COLOR_BLACK)) {
        if (node == parent->left) {
            struct tree_node* sibling = parent->right;
            if (color(sibling) == COLOR_RED) {
                set_color(sibling, COLOR_BLACK);
                set_color(parent, COLOR_RED);
                rotate_left(tree, parent);
                sibling = parent->right;
            }
            if ((!sibling->left || color(sibling->left) == COLOR_BLACK) &&
                (!sibling->right || color(sibling->right) == COLOR_BLACK)) {
                set_color(sibling, COLOR_RED);
                node = parent;
            } else {
                if (!sibling->right || color(sibling->right) == COLOR_BLACK) {
                    set_color(sibling->left, COLOR_BLACK);
                    set_color(sibling, COLOR_RED);
                    rotate_right(tree, sibling);
                    sibling = parent->right;
                }
                set_color(sibling, color(parent));
                set_color(parent, COLOR_BLACK);
                set_color(sibling->right, COLOR_BLACK);
                rotate_left(tree, parent);
                node = tree->root;
            }
        } else {
            struct tree_node* sibling = parent->left;
            if (color(sibling) == COLOR_RED) {
                set_color(sibling, COLOR_BLACK);
                set_color(parent, COLOR_RED);
                rotate_right(tree, parent);
                sibling = parent->left;
            }
            if ((!sibling->left || color(sibling->left) == COLOR_BLACK) &&
                (!sibling->right || color(sibling->right) == COLOR_BLACK)) {
                set_color(sibling, COLOR_RED);
                node = parent;
            } else {
                if (!sibling->left || color(sibling->left) == COLOR_BLACK) {
                    set_color(sibling->right, COLOR_BLACK);
                    set_color(sibling, COLOR_RED);
                    rotate_left(tree, sibling);
                    sibling = parent->left;
                }
                set_color(sibling, color(parent));
                set_color(parent, COLOR_BLACK);
                set_color(sibling->left, COLOR_BLACK);
                rotate_right(tree, parent);
                node = tree->root;
            }
        }
        parent = tree_parent(node);
    }

    set_color(node, COLOR_BLACK);
}

void tree_remove(struct tree* tree, struct tree_node* node) {
    ASSERT(node);

    if (node->left && node->right) {
        struct tree_node* successor = tree_next(node);
        bool neighbor_swap = tree_parent(successor) == node;
        set_parent(node->left, successor);
        if (!neighbor_swap)
            set_parent(node->right, successor);
        replace_child(tree, tree_parent(node), node, successor);
        if (successor->right)
            set_parent(successor->right, node);
        if (neighbor_swap) {
            set_parent(successor, tree_parent(node));
            set_parent(node, successor);
        } else {
            replace_child(tree, tree_parent(successor), successor, node);
            swap_parent(node, successor);
        }
        swap_node(&node->left, &successor->left);
        if (neighbor_swap) {
            node->right = successor->right;
            successor->right = node;
        } else {
            swap_node(&node->right, &successor->right);
        }
        swap_color(node, successor);
    }

    struct tree_node* child = node->left ? node->left : node->right;
    if (child)
        set_parent(child, tree_parent(node));
    replace_child(tree, tree_parent(node), node, child);

    if (tree->root && color(node) == COLOR_BLACK)
        balance_after_removal(tree, tree_parent(node), child);

    node->parent_and_color = 0;
    node->left = node->right = NULL;
}

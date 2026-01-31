#include <common/macros.h>
#include <common/random.h>
#include <common/tree.h>
#include <stdlib.h>

static uint32_t random_state[4] = {0x12345678, 0x23456789, 0x34567890,
                                   0x45678901};

static uint32_t random_next(void) {
    return xoshiro128plusplus_next(random_state);
}

#define NUM_NODES 3000

struct node {
    uint32_t value;
    struct tree_node tree_node;
};

static void validate(struct tree* tree, size_t count) {
    uint32_t last_value = 0;
    size_t i = 0;
    for (struct tree_node* node = tree_first(tree); node;
         node = tree_next(node)) {
        struct node* n = CONTAINER_OF(node, struct node, tree_node);
        ASSERT(n->value > last_value);
        last_value = n->value;
        ++i;
    }
    ASSERT(i == count);

    last_value = UINT32_MAX;
    i = 0;
    for (struct tree_node* node = tree_last(tree); node;
         node = tree_prev(node)) {
        struct node* n = CONTAINER_OF(node, struct node, tree_node);
        ASSERT(n->value < last_value);
        last_value = n->value;
        ++i;
    }
    ASSERT(i == count);
}

static void remove_first(struct tree* tree) {
    for (int count = NUM_NODES; count > 0; --count) {
        struct tree_node* node = tree_first(tree);
        tree_remove(tree, node);
        validate(tree, count - 1);
    }
    ASSERT(tree_is_empty(tree));
}

static void remove_last(struct tree* tree) {
    for (int count = NUM_NODES; count > 0; --count) {
        struct tree_node* node = tree_last(tree);
        tree_remove(tree, node);
        validate(tree, count - 1);
    }
    ASSERT(tree_is_empty(tree));
}

static void remove_root(struct tree* tree) {
    for (int count = NUM_NODES; count > 0; --count) {
        struct tree_node* node = tree->root;
        tree_remove(tree, node);
        validate(tree, count - 1);
    }
    ASSERT(tree_is_empty(tree));
}

static void remove_random(struct tree* tree) {
    for (int count = NUM_NODES; count > 0; --count) {
        size_t r = random_next() % count;
        struct tree_node* node = tree_first(tree);
        for (size_t i = 0; i < r; ++i)
            node = tree_next(node);
        tree_remove(tree, node);
        validate(tree, count - 1);
    }
    ASSERT(tree_is_empty(tree));
}

int main(void) {
    struct node* nodes = malloc(NUM_NODES * sizeof(struct node));
    ASSERT(nodes);

    void (*test_cases[])(struct tree*) = {
        remove_first,
        remove_last,
        remove_root,
        remove_random,
    };
    for (size_t i = 0; i < ARRAY_SIZE(test_cases); ++i) {
        struct tree tree = {0};

        for (size_t i = 0; i < NUM_NODES; ++i) {
        retry:;
            uint32_t value = random_next();
            if (value == 0 || value == UINT32_MAX)
                goto retry;

            struct tree_node* parent = NULL;
            struct tree_node** new_node = &tree.root;
            while (*new_node) {
                parent = *new_node;
                struct node* n = CONTAINER_OF(parent, struct node, tree_node);
                if (value < n->value)
                    new_node = &parent->left;
                else if (value > n->value)
                    new_node = &parent->right;
                else
                    goto retry;
            }

            nodes[i].value = value;
            *new_node = &nodes[i].tree_node;
            tree_insert(&tree, parent, *new_node);
        }

        test_cases[i](&tree);
    }

    return EXIT_SUCCESS;
}

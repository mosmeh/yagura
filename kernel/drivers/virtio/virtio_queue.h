#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct virtq_desc {
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;

/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT 1
/* This marks a buffer as write-only (otherwise read-only). */
#define VIRTQ_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT 4
    /* The flags as indicated above. */
    uint16_t flags;
    /* Next field if flags & NEXT */
    uint16_t next;
};

struct virtq_avail {
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
};

struct virtq_used_elem {
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /*
     * The number of bytes written into the device writable portion of
     * the buffer described by the descriptor chain.
     */
    uint32_t len;
};

struct virtq_used {
#define VIRTQ_USED_F_NO_NOTIFY 1
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
};

struct virtq {
    uint16_t index;               // The index of the queue
    size_t size;                  // The number of descriptors
    atomic_size_t num_free_descs; // The number of free descriptors
    size_t free_head;             // The index of the first free descriptor
    uint16_t avail_index_shadow;  // The copy of avail->idx

    // The actual descriptors (16 bytes each)
    struct virtq_desc* desc;

    // A ring of available descriptor heads with free-running index.
    struct virtq_avail* avail;

    // A ring of used descriptor heads with free-running index.
    volatile struct virtq_used* used;

    uint16_t* notify; // The notification address
};

bool virtq_is_ready(const struct virtq*);

struct virtq_desc_chain {
    struct virtq* virtq;
    size_t num_pushed;
    uint16_t head;
    uint16_t tail;
};

bool virtq_desc_chain_init(struct virtq_desc_chain*, struct virtq*,
                           size_t num_descriptors);
void virtq_desc_chain_push_buf(struct virtq_desc_chain*, void* buf, size_t len,
                               bool device_writable);
int virtq_desc_chain_submit(struct virtq_desc_chain*);

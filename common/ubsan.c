#include <common/panic.h>
#include <common/stdbool.h>
#include <common/stdint.h>

struct source_location {
    const char* filename;
    uint32_t line;
    uint32_t column;
};

struct type_descriptor {
    uint16_t kind;
    uint16_t info;
    char name[];
};

struct invalid_value_data {
    struct source_location location;
    const struct type_descriptor* type;
};

void __ubsan_handle_load_invalid_value(const struct invalid_value_data* data,
                                       const void* ptr) {
    (void)ptr;
    PANIC("ubsan: load invalid value: type=%s", data->type->name);
}

struct nonnull_arg_data {
    struct source_location location;
    struct source_location attribute_location;
    int argument_index;
};

void __ubsan_handle_nonnull_arg(const struct nonnull_arg_data* data) {
    (void)data;
    PANIC("ubsan: nonnull argument");
}

struct overflow_data {
    struct source_location location;
    const struct type_descriptor* type;
};

void __ubsan_handle_add_overflow(const struct overflow_data* data,
                                 const void* lhs, const void* rhs) {
    (void)lhs;
    (void)rhs;
    PANIC("ubsan: add overflow: type=%s", data->type->name);
}

void __ubsan_handle_sub_overflow(const struct overflow_data* data,
                                 const void* lhs, const void* rhs) {
    (void)lhs;
    (void)rhs;
    PANIC("ubsan: sub overflow: type=%s", data->type->name);
}

void __ubsan_handle_negate_overflow(const struct overflow_data* data,
                                    const void* ptr) {
    (void)ptr;
    PANIC("ubsan: negate overflow: type=%s", data->type->name);
}

void __ubsan_handle_mul_overflow(const struct overflow_data* data,
                                 const void* lhs, const void* rhs) {
    (void)lhs;
    (void)rhs;
    PANIC("ubsan: mul overflow: type=%s", data->type->name);
}

struct shift_out_of_bounds_data {
    struct source_location location;
    const struct type_descriptor* lhs_type;
    const struct type_descriptor* rhs_type;
};

void __ubsan_handle_shift_out_of_bounds(
    const struct shift_out_of_bounds_data* data, const void* lhs,
    const void* rhs) {
    (void)lhs;
    (void)rhs;
    PANIC("ubsan: shift out of bounds: lhs=%s rhs=%s", data->lhs_type->name,
          data->rhs_type->name);
}

void __ubsan_handle_divrem_overflow(const struct overflow_data* data,
                                    const void* lhs, const void* rhs) {
    (void)lhs;
    (void)rhs;
    PANIC("ubsan: divrem overflow: type=%s", data->type->name);
}

struct out_of_bounds_data {
    struct source_location location;
    const struct type_descriptor* array_type;
    const struct type_descriptor* index_type;
};

void __ubsan_handle_out_of_bounds(const struct out_of_bounds_data* data,
                                  const void* index) {
    (void)index;
    PANIC("ubsan: out of bounds: array=%s index=%s", data->array_type->name,
          data->index_type->name);
}

struct type_mismatch_data {
    struct source_location location;
    const struct type_descriptor* type;
    uint8_t log_alignment;
    uint8_t type_check_kind;
};

void __ubsan_handle_type_mismatch_v1(const struct type_mismatch_data* data,
                                     const void* ptr) {
    unsigned alignment = 1U << data->log_alignment;
    bool aligned = ((uintptr_t)ptr & (alignment - 1)) == 0;
    PANIC("ubsan: type mismatch: ptr=0x%p type=%s kind=%u alignment=%u (%s)\n",
          ptr, data->type->name, data->type_check_kind, alignment,
          aligned ? "aligned" : "misaligned");
}

struct unreachable_data {
    struct source_location location;
};

void __ubsan_handle_builtin_unreachable(const struct unreachable_data* data) {
    (void)data;
    PANIC("ubsan: builtin unreachable");
}

struct invalid_builtin_data {
    struct source_location location;
    uint8_t kind;
};

void __ubsan_handle_invalid_builtin(const struct invalid_builtin_data* data) {
    PANIC("ubsan: invalid builtin: kind=%u", data->kind);
}

struct pointer_overflow_data {
    struct source_location location;
};

void __ubsan_handle_pointer_overflow(const struct pointer_overflow_data* data,
                                     const void* base, const void* result) {
    (void)data;
    PANIC("ubsan: pointer overflow: base=0x%p result=0x%p", base, result);
}

#include "psf.h"
#include <common/extra.h>
#include <common/string.h>
#include <kernel/api/err.h>
#include <kernel/api/fcntl.h>
#include <kernel/api/stdio.h>
#include <kernel/fs/fs.h>
#include <kernel/fs/path.h>
#include <kernel/memory/memory.h>

static struct font* load_psf1(struct file* file) {
    struct psf1_header header;
    if (file_read_to_end(file, &header, sizeof(struct psf1_header)) !=
        sizeof(struct psf1_header)) {
        return ERR_PTR(-EINVAL);
    }
    if (header.magic[0] != PSF1_MAGIC0 || header.magic[1] != PSF1_MAGIC1)
        return ERR_PTR(-EINVAL);

    struct font* font = kmalloc(sizeof(struct font));
    if (!font)
        return ERR_PTR(-ENOMEM);

    font->glyph_width = 8;
    font->glyph_height = font->bytes_per_glyph = header.charsize;

    size_t num_glyphs = (header.mode & PSF1_MODE512) ? 512 : 256;
    size_t buf_size = num_glyphs * font->glyph_height;
    font->glyphs = kmalloc(buf_size);
    if (!font->glyphs) {
        kfree(font);
        return ERR_PTR(-ENOMEM);
    }
    if ((size_t)file_read_to_end(file, font->glyphs, buf_size) != buf_size) {
        kfree(font->glyphs);
        kfree(font);
        return ERR_PTR(-EINVAL);
    }

    if (header.mode & PSF1_MODEHASTAB) {
        memset(font->ascii_to_glyph, 0, sizeof(font->ascii_to_glyph));
        for (size_t i = 0; i < num_glyphs; ++i) {
            for (;;) {
                uint16_t uc;
                if (file_read_to_end(file, &uc, sizeof(uint16_t)) !=
                    sizeof(uint16_t)) {
                    kfree(font->glyphs);
                    kfree(font);
                    return ERR_PTR(-EINVAL);
                }
                if (uc == PSF1_SEPARATOR)
                    break;
                if (uc < 128)
                    font->ascii_to_glyph[uc] = i;
            }
        }
    } else {
        for (size_t i = 0; i < 128; ++i)
            font->ascii_to_glyph[i] = i;
    }

    return font;
}

static struct font* load_psf2(struct file* file) {
    struct psf2_header header;
    if (file_read_to_end(file, &header, sizeof(struct psf2_header)) !=
        sizeof(struct psf2_header))
        return ERR_PTR(-EINVAL);
    if (header.magic != PSF2_MAGIC || header.version != 0 ||
        header.headersize != sizeof(struct psf2_header))
        return ERR_PTR(-EINVAL);

    struct font* font = kmalloc(sizeof(struct font));
    if (!font)
        return ERR_PTR(-ENOMEM);

    font->glyph_width = header.width;
    font->glyph_height = header.height;
    font->bytes_per_glyph = header.bytesperglyph;
    if (DIV_CEIL(font->glyph_width, 8) * font->glyph_height !=
        font->bytes_per_glyph) {
        kfree(font);
        return ERR_PTR(-EINVAL);
    }

    size_t buf_size = header.numglyph * font->bytes_per_glyph;
    font->glyphs = kmalloc(buf_size);
    if (!font->glyphs) {
        kfree(font);
        return ERR_PTR(-ENOMEM);
    }
    if ((size_t)file_read_to_end(file, font->glyphs, buf_size) != buf_size) {
        kfree(font->glyphs);
        kfree(font);
        return ERR_PTR(-EINVAL);
    }

    if (header.flags & PSF2_HAS_UNICODE_TABLE) {
        memset(font->ascii_to_glyph, 0, sizeof(font->ascii_to_glyph));
        for (size_t i = 0; i < header.numglyph; ++i) {
            for (;;) {
                uint8_t uc;
                if (file_read_to_end(file, &uc, sizeof(uint8_t)) !=
                    sizeof(uint8_t)) {
                    kfree(font->glyphs);
                    kfree(font);
                    return ERR_PTR(-EINVAL);
                }
                if (uc == PSF2_SEPARATOR)
                    break;
                if (uc < 128)
                    font->ascii_to_glyph[uc] = i;
            }
        }
    } else {
        for (size_t i = 0; i < 128; ++i)
            font->ascii_to_glyph[i] = i;
    }

    return font;
}

struct font* load_psf(const char* filename) {
    struct path* root = vfs_get_root();
    if (IS_ERR(root))
        return ERR_CAST(root);

    struct font* ret = NULL;

    struct file* file = vfs_open_at(root, filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        ret = ERR_CAST(file);
        file = NULL;
        goto done;
    }

    ret = load_psf1(file);
    if (IS_OK(ret))
        goto done;

    int rc = file_seek(file, 0, SEEK_SET);
    if (IS_ERR(rc)) {
        ret = ERR_PTR(rc);
        goto done;
    }

    ret = load_psf2(file);
    if (IS_OK(ret))
        goto done;

    ret = ERR_PTR(-EINVAL);

done:
    if (file)
        file_unref(file);
    path_destroy_recursive(root);
    return ret;
}

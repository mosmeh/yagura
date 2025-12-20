#include <kernel/console/screen/screen.h>
#include <kernel/panic.h>

struct screen* fb_screen_init(void);
struct screen* vga_text_screen_init(void);

struct screen* screen_init(void) {
    struct screen* screen = fb_screen_init();
    if (IS_OK(screen))
        return screen;

    screen = vga_text_screen_init();
    if (IS_OK(screen))
        return screen;

    return ERR_PTR(-ENODEV);
}

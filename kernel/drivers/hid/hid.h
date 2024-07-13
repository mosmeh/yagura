#pragma once

struct key_event;

typedef void (*ps2_key_event_handler_fn)(const struct key_event*);
void ps2_set_key_event_handler(ps2_key_event_handler_fn);

#pragma once

int mount(const char* source, const char* target, const char* filesystemtype,
          unsigned long mountflags, const void* data);

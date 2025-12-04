# Kernel command-line parameters

The kernel command-line parameters are in the form of `key=value`, where the `=value` part is optional depending on the parameter. Multiple parameters are separated by spaces.

- `init=<path>`: The path to the init program. If not specified or the kernel is not able to execute the specified program, it will try the following paths in order:
   - `/sbin/init`
   - `/etc/init`
   - `/bin/init`
   - `/bin/sh`
- `panic=<timeout>`: Defines the behavior of the kernel when a panic occurs.
   - `timeout` > `0`: Wait for the specified number of seconds and then reboot the system.
   - `timeout` = `0`: Halt the system.
   - `timeout` < `0`: Reboot the system.
   - `timeout` = `poweroff`: Power off the system.
- `console=<device>`: The device to use as the system console `/dev/console`. The default is `tty1`.
- `nosmp`: Disables symmetric multiprocessing.
- `ni_syscall_log`: Log a message when an unimplemented system call is invoked.

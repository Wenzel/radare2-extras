#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>

static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
    printf("%s\n", __func__);
}

static int __close(RIODesc *fd) {
    printf("%s\n", __func__);

}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
    printf("%s\n", __func__);

}

static bool __plugin_open(RIO *io, const char *file, bool many) {
    printf("%s\n", __func__);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
    printf("%s\n", __func__);

}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
    printf("%s\n", __func__);

}

static int __system(RIO *io, RIODesc *fd, const char *command) {
    printf("%s\n", __func__);

}

RIOPlugin r_io_plugin_vmi = {
    .name = "vmi",
    .desc = "VMI IO plugin for r2 vmi://[vm_name]:[pid]",
    .license = "LGPL",
    .open = __open,
    .close = __close,
    .read = __read,
    .check = __plugin_open,
    .lseek = __lseek,
    .write = __write,
    .system = __system,
    .isdbg = true,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_IO,
    .data = &r_io_plugin_vmi,
    .version = R2_VERSION
};
#endif

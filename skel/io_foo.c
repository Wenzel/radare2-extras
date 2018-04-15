#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "io_foo.h"

#define URI_PREFIX "foo://"

extern RIOPlugin r_io_plugin_foo; // forward declaration

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
    return (strncmp(pathname, URI_PREFIX, strlen(URI_PREFIX)) == 0);
}

static RIODesc *__open(RIO *io, const char *pathname, int flags, int mode) {
    RIODesc *ret = NULL;
    RIOFoo *rio_foo = NULL;

    printf("%s\n", __func__);

    if (!__plugin_open(io, pathname, 0))
        return ret;

    return r_io_desc_new (io, &r_io_plugin_foo, pathname, flags, mode, rio_foo);
}

static int __close(RIODesc *fd) {
    RIOFoo *rio_foo = NULL;

    printf("%s\n", __func__);
    if (!fd || !fd->data)
        return -1;

    rio_foo = fd->data;
    // destroy
    return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
    printf("%s, offset: %llx, io->off: %llx\n", __func__, offset, io->off);

    if (!fd || !fd->data)
        return -1;

    switch (whence) {
    case SEEK_SET:
        io->off = offset;
        break;
    case SEEK_CUR:
        io->off += (int)offset;
        break;
    case SEEK_END:
        io->off = UT64_MAX;
        break;
    }
    return io->off;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
    RIOFoo *rio_foo = NULL;

    printf("%s, offset: %llx\n", __func__, io->off);

    if (!fd || !fd->data)
        return -1;

    rio_foo = fd->data;

    return 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
    printf("%s\n", __func__);

    return 0;
}

static int __getpid(RIODesc *fd) {
    RIOFoo *rio_foo = NULL;

    printf("%s\n", __func__);
    if (!fd || !fd->data)
        return -1;

    rio_foo = fd->data;
    return 0;
}

static int __gettid(RIODesc *fd) {
    printf("%s\n", __func__);
    return 0;
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
    printf("%s command: %s\n", __func__, command);
    // io->cb_printf()
    return NULL;
}

RIOPlugin r_io_plugin_foo = {
    .name = "foo",
    .desc = "IO Foo plugin",
    .license = "LGPL",
    .check = __plugin_open,
    .open = __open,
    .close = __close,
    .lseek = __lseek,
    .read = __read,
    .write = __write,
    .getpid = __getpid,
    .system = __system,
    .isdbg = true,  // # --d flag
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_IO,
    .data = &r_io_plugin_foo,
    .version = R2_VERSION
};
#endif

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define URI_PREFIX "vmi://"

typedef struct {
    char *vm_name;
    int pid;
} RIOVmi;

static RIOVmi *rio_vmi = NULL;

static bool __plugin_open(RIO *io, const char *file, bool many) {
    return (strncmp(file, URI_PREFIX, strlen(URI_PREFIX)) == 0);
}

static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
    RIODesc *ret = NULL;
    RIOVmi *_rio_vmi = NULL;
    const char *delimiter = ":";
    char *vm_name = NULL;
    long pid = 0;
    char *uri_content = NULL;
    char *saveptr = NULL;

    if (!__plugin_open(io, file, 0))
        return ret;

    // allocate RIOVmi
    _rio_vmi = R_NEW0(RIOVmi);

    // URI has the following format: vmi://vm_name:pid
    // parse URI

    uri_content = strdup(file + strlen(URI_PREFIX));
    // get vm_name
    char *token = strtok_r(uri_content, delimiter, &saveptr);
    _rio_vmi->vm_name = strdup(token);
    vm_name = NULL;
    // get pid
    token = strtok_r(NULL, delimiter, &saveptr);
    saveptr = NULL;
    pid = strtol(token, &saveptr, 10);
    if (!pid || errno == ERANGE)
    {
        fprintf(stderr, "strtol: Could not convert %s to int.\n", token);
        goto out;
    }
    _rio_vmi->pid = pid;

    return ret;

out:
    if (_rio_vmi)
    {
        if (_rio_vmi->vm_name)
            free(_rio_vmi->vm_name);
        free(_rio_vmi);
    }
    if (vm_name)
        free(vm_name);

    return ret;
}

static int __close(RIODesc *fd) {
    if (!rio_vmi)
    {
        free(rio_vmi->vm_name);
        free(rio_vmi);
    }
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
    printf("%s\n", __func__);

}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
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
    .check = __plugin_open,
    .open = __open,
    .close = __close,
    .lseek = __lseek,
    .read = __read,
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

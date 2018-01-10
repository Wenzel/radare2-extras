#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <libvmi/libvmi.h>

#define URI_PREFIX "vmi://"

typedef struct {
    char *vm_name;
    int pid;
    vmi_instance_t vmi;
} RIOVmi;

extern RIOPlugin r_io_plugin_vmi; // forward declaration

static void rio_vmi_destroy(RIOVmi *ptr)
{
    if (ptr)
    {
        if (ptr->vm_name)
            free(ptr->vm_name);
        if (ptr->vmi)
            vmi_destroy(ptr->vmi);
        free(ptr);
    }
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
    return (strncmp(pathname, URI_PREFIX, strlen(URI_PREFIX)) == 0);
}

static RIODesc *__open(RIO *io, const char *pathname, int flags, int mode) {
    printf("%s\n", __func__);
    RIODesc *ret = NULL;
    RIOVmi *rio_vmi = NULL;
    const char *delimiter = ":";
    long pid = 0;
    char *uri_content = NULL;
    char *saveptr = NULL;

    if (!__plugin_open(io, pathname, 0))
        return ret;

    // allocate RIOVmi
    rio_vmi = R_NEW0(RIOVmi);
    if (!rio_vmi)
        goto out;

    // URI has the following format: vmi://vm_name:pid
    // parse URI
    uri_content = strdup(pathname + strlen(URI_PREFIX));
    // get vm_name
    char *token = strtok_r(uri_content, delimiter, &saveptr);
    if (!token)
    {
        eprintf("strtok_r: Parsing vm_name failed\n");
        goto out;
    }
    rio_vmi->vm_name = strdup(token);
    // get pid
    token = strtok_r(NULL, delimiter, &saveptr);
    if (!token)
    {
        eprintf("strtok_r: Parsing pid failed\n");
        goto out;
    }
    saveptr = NULL;
    pid = strtol(token, &saveptr, 10);
    if (!pid)
    {
        eprintf("strtol: Could not convert %s to int. (%s)\n", token, strerror(errno));
        goto out;
    }
    if (*saveptr != '\0')
    {
        eprintf("strtol: Could not entirely convert %s to int, (%s)\n", token, saveptr);
        goto out;
    }
    rio_vmi->pid = pid;
    printf("VM: %s, PID: %d\n", rio_vmi->vm_name, rio_vmi->pid);

    // init libvmi
    printf("Initializing LibVMI\n");
    vmi_init_error_t error;
    status_t status = vmi_init_complete(&(rio_vmi->vmi), rio_vmi->vm_name, VMI_INIT_DOMAINNAME, NULL,
                                        VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, &error);
    if (status == VMI_FAILURE)
    {
        eprintf("vmi_init_complete: Failed to initialize LibVMI, error: %d\n", error);
        goto out;
    }

    return r_io_desc_new (io, &r_io_plugin_vmi, pathname, flags, mode, rio_vmi);

out:
    if (uri_content)
        free(uri_content);
    rio_vmi_destroy(rio_vmi);
    return ret;
}

static int __close(RIODesc *fd) {
    RIOVmi *rio_vmi = NULL;

    printf("%s\n", __func__);
    if (!fd || !fd->data)
        return -1;

    rio_vmi = fd->data;
    rio_vmi_destroy(rio_vmi);
    return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
    printf("%s, offset: %llx\n", __func__, offset);

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
    RIOVmi *rio_vmi = NULL;
    status_t status;
    size_t bytes_read = 0;
    access_context_t ctx;

    printf("%s, offset: %llx\n", __func__, io->off);

    if (!fd || !fd->data)
        return -1;

    rio_vmi = fd->data;
    // fill access context
    ctx.translate_mechanism = VMI_TM_PROCESS_PID;
    ctx.addr = io->off;
    ctx.pid = rio_vmi->pid;
    // read
    status = vmi_read(rio_vmi->vmi, &ctx, len, (void*)buf, &bytes_read);
    if (status == VMI_FAILURE)
    {
        eprintf("read: vmi_failure\n");
        return 0;
    }

    return bytes_read;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
    printf("%s\n", __func__);

}

static int __getpid(RIODesc *fd) {
    printf("%s\n", __func__);

    RIOVmi *rio_vmi = NULL;

    printf("%s\n", __func__);
    if (!fd || !fd->data)
        return -1;

    rio_vmi = fd->data;
    return rio_vmi->pid;
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
    .getpid = __getpid,
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

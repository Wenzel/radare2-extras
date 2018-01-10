#include <r_asm.h>
#include <r_debug.h>

static int r_debug_vmi_step(RDebug *dbg) {
    printf("%s\n", __func__);

}

static int r_debug_vmi_continue(RDebug *dbg, int pid, int tid, int sig) {
    printf("%s\n", __func__);

}

static int r_debug_vmi_attach(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static int r_debug_vmi_detach(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static RList* r_debug_vmi_threads(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static RDebugReasonType r_debug_vmi_wait(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static RList *r_debug_vmi_map_get(RDebug* dbg) {
    printf("%s\n", __func__);

}

static RList* r_debug_vmi_modules_get(RDebug *dbg) {
    printf("%s\n", __func__);

}

static int r_debug_vmi_breakpoint (void *bp, RBreakpointItem *b, bool set) {
    printf("%s\n", __func__);

}

static const char *r_debug_vmi_reg_profile(RDebug *dbg) {
    printf("%s\n", __func__);

}

static bool r_debug_vmi_kill(RDebug *dbg, int pid, int tid, int sig) {
    printf("%s\n", __func__);

}

static int r_debug_vmi_select(int pid, int tid) {
    printf("%s\n", __func__);

}

static RDebugInfo* r_debug_vmi_info(RDebug *dbg, const char *arg) {
    printf("%s\n", __func__);

}

static RList* r_debug_vmi_frames(RDebug *dbg, ut64 at) {
    printf("%s\n", __func__);

}

static int r_debug_vmi_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
    printf("%s\n", __func__);
    return 0;
}

RDebugPlugin r_debug_plugin_vmi = {
    .name = "vmi",
    /* TODO: Add support for more architectures here */
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
    .step = r_debug_vmi_step,
    .cont = r_debug_vmi_continue,
    .attach = &r_debug_vmi_attach,
    .detach = &r_debug_vmi_detach,
    .threads = &r_debug_vmi_threads,
    .wait = &r_debug_vmi_wait,
    .map_get = r_debug_vmi_map_get,
    .modules_get = r_debug_vmi_modules_get,
    .breakpoint = &r_debug_vmi_breakpoint,
    .reg_profile = (void *)r_debug_vmi_reg_profile,
    .kill = &r_debug_vmi_kill,
    .info = &r_debug_vmi_info,
    .select = &r_debug_vmi_select,
    .frames = &r_debug_vmi_frames,
    .reg_read = &r_debug_vmi_reg_read,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_DBG,
    .data = &r_debug_plugin_vmi,
    .version = R2_VERSION
};
#endif

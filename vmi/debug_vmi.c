#include <r_asm.h>
#include <r_debug.h>

static int r_debug_vmi_step(RDebug *dbg) {
    printf("%s\n", __func__);

}

// "dc" continue execution
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

// "drp" register profile
static const char *r_debug_vmi_reg_profile(RDebug *dbg) {
    printf("%s\n", __func__);
    int arch = r_sys_arch_id (dbg->arch);
    int bits = dbg->anal->bits;

    switch (arch) {
        case R_SYS_ARCH_X86:
            switch (bits) {
                case 32:
                    return strdup (
                            "=PC	eip\n"
                            "=SP	esp\n"
                            "=BP	ebp\n"
                            "=A0	eax\n"
                            "=A1	ebx\n"
                            "=A2	ecx\n"
                            "=A3	edx\n"
                            "=SN	oeax\n"
                            "gpr	eax	.32	0	0\n"
                            "gpr	ecx	.32	4	0\n"
                            "gpr	edx	.32	8	0\n"
                            "gpr	ebx	.32	12	0\n"
                            "gpr	esp	.32	16	0\n"
                            "gpr	ebp	.32	20	0\n"
                            "gpr	esi	.32	24	0\n"
                            "gpr	edi	.32	28	0\n"
                            "gpr	eip	.32	32	0\n"
                            "gpr	eflags	.32	36	0\n"
                            "seg	cs	.32	40	0\n"
                            "seg	ss	.32	44	0\n"
                            "seg	ds	.32	48	0\n"
                            "seg	es	.32	52	0\n"
                            "seg	fs	.32	56	0\n"
                            "seg	gs	.32	60	0\n"
                            "fpu	st0	.80	64	0\n"
                            "fpu	st1	.80	74	0\n"
                            "fpu	st2	.80	84	0\n"
                            "fpu	st3	.80	94	0\n"
                            "fpu	st4	.80	104	0\n"
                            "fpu	st5	.80	114	0\n"
                            "fpu	st6	.80	124	0\n"
                            "fpu	st7	.80	134	0\n"
                            "gpr	fctrl	.32	144	0\n"
                            "gpr	fstat	.32	148	0\n"
                            "gpr	ftag	.32	152	0\n"
                            "gpr	fiseg	.32	156	0\n"
                            "gpr	fioff	.32	160	0\n"
                            "gpr	foseg	.32	164	0\n"
                            "gpr	fooff	.32	168	0\n"
                            "gpr	fop	.32	172	0\n"
                            );
                            break;
                case 64:
                    return strdup (
                            "=PC	rip\n"
                            "=SP	rsp\n"
                            "=BP	rbp\n"
                            "=A0	rax\n"
                            "=A1	rbx\n"
                            "=A2	rcx\n"
                            "=A3	rdx\n"
                            "=SN	orax\n"
                            "gpr	fake	.64	795	0\n"
                            "gpr	rax	.64	0	0\n"
                            "gpr	rbx	.64	8	0\n"
                            "gpr	rcx	.64	16	0\n"
                            "gpr	rdx	.64	24	0\n"
                            "gpr	rsi	.64	32	0\n"
                            "gpr	rdi	.64	40	0\n"
                            "gpr	rbp	.64	48	0\n"
                            "gpr	rsp	.64	56	0\n"
                            "gpr	r8	.64	64	0\n"
                            "gpr	r9	.64	72	0\n"
                            "gpr	r10	.64	80	0\n"
                            "gpr	r11	.64	88	0\n"
                            "gpr	r12	.64	96	0\n"
                            "gpr	r13	.64	104	0\n"
                            "gpr	r14	.64	112	0\n"
                            "gpr	r15	.64	120	0\n"
                            "gpr	rip	.64	128	0\n"
                            "gpr	eflags	.32	136	0\n"
                            "seg	cs	.32	140	0\n"
                            "seg	ss	.32	144	0\n"
                            "seg	ds	.32	148	0\n"
                            "seg	es	.32	152	0\n"
                            "seg	fs	.32	156	0\n"
                            "seg	gs	.32	160	0\n"
                            "fpu	st0	.80	164	0\n"
                            "fpu	st1	.80	174	0\n"
                            "fpu	st2	.80	184	0\n"
                            "fpu	st3	.80	194	0\n"
                            "fpu	st4	.80	204	0\n"
                            "fpu	st5	.80	214	0\n"
                            "fpu	st6	.80	224	0\n"
                            "fpu	st7	.80	234	0\n"
                            "gpr	fctrl	.32	244	0\n"
                            "gpr	fstat	.32	248	0\n"
                            "gpr	ftag	.32	252	0\n"
                            "gpr	fiseg	.32	256	0\n"
                            "gpr	fioff	.32	260	0\n"
                            "gpr	foseg	.32	264	0\n"
                            "gpr	fooff	.32	268	0\n"
                            "gpr	fop	.32	272	0\n"
                            );
                            break;
                default:
                    eprintf("bit size not supported by vmi debugger\n");
                    return NULL;

            }
            break;
        default:
            eprintf("Architecture not supported by vmi debugger\n");
            return NULL;
    }

}

// "dk" send kill signal
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
    printf("%s, type: %d, size:%d\n", __func__, type, size);

    return 0;
}

RDebugPlugin r_debug_plugin_vmi = {
    .name = "vmi",
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
    .step = &r_debug_vmi_step,
    .cont = &r_debug_vmi_continue,
    .attach = &r_debug_vmi_attach,
    .detach = &r_debug_vmi_detach,
    .threads = &r_debug_vmi_threads,
    .wait = &r_debug_vmi_wait,
    .map_get = &r_debug_vmi_map_get,
    .modules_get = &r_debug_vmi_modules_get,
    .breakpoint = &r_debug_vmi_breakpoint,
    .reg_profile = (void*) &r_debug_vmi_reg_profile,
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

#include <r_asm.h>
#include <r_debug.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include "io_vmi.h"

// vmi_events_listen loop
static bool interrupted = false;

typedef struct {
    pid_t pid;
    registers_t regs;
    status_t status;
} cr3_load_event_data_t;



static int __step(RDebug *dbg) {
    printf("%s\n", __func__);

}

// "dc" continue execution
static int __continue(RDebug *dbg, int pid, int tid, int sig) {
    printf("%s\n", __func__);

}

event_response_t cb_on_cr3_load(vmi_instance_t vmi, vmi_event_t *event){
    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_REGISTER || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event data
    cr3_load_event_data_t event_data = *(cr3_load_event_data_t*)(event->data);

    reg_t cr3 = event->reg_event.value;
    pid_t pid;
    status_t status = vmi_dtb_to_pid(vmi, (addr_t) cr3, &pid);
    if (status == VMI_FAILURE)
    {
        eprintf("ERROR (%s): fail to retrieve pid from cr3\n", __func__);
        return 0;
    }

    printf("pid: %d, cr3: %lx, target pid: %d\n", pid, cr3, event_data.pid);
    // check if it's our pid
    if (pid == event_data.pid)
    {
        // stop monitoring
        interrupted = true;
        status = vmi_clear_event(vmi, event, NULL);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to clear event\n");
            exit(1);
        }
    }

    return 0;
}

static int __attach(RDebug *dbg, int pid) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status = 0;

    printf("Attaching to pid %d...\n", pid);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    status = vmi_pause_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to pause VM\n");
        return 1;
    }

    vmi_event_t cr3_load_event = {0};
    SETUP_REG_EVENT(&cr3_load_event, CR3, VMI_REGACCESS_W, 0, cb_on_cr3_load);

    // preparing event data
    cr3_load_event_data_t event_data = {0};
    event_data.pid = rio_vmi->pid;

    // add it to cr3_load_event
    cr3_load_event.data = (void*)&event_data;

    status = vmi_register_event(rio_vmi->vmi, &cr3_load_event);
    if (status == VMI_FAILURE)
    {
        eprintf("vmi event registration failure\n");
        vmi_resume_vm(rio_vmi->vmi);
        return 0;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume VM\n");
        return 1;
    }
    while (!interrupted)
    {
        printf("Listening on VMI events...\n");
        status = vmi_events_listen(rio_vmi->vmi, 1000);
        if (status == VMI_FAILURE)
        {
            interrupted = true;
        }
    }

    // pause vm
    status = vmi_pause_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to pause VM\n");
        return 1;
    }

    return 0;

}

static int __detach(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static RList* __threads(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static RDebugReasonType __wait(RDebug *dbg, int pid) {
    printf("%s\n", __func__);

}

static RList *__map_get(RDebug* dbg) {
    printf("%s\n", __func__);

}

static RList* __modules_get(RDebug *dbg) {
    printf("%s\n", __func__);

}

static int __breakpoint (void *bp, RBreakpointItem *b, bool set) {
    printf("%s\n", __func__);



}

// "drp" register profile
static const char *__reg_profile(RDebug *dbg) {
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
static bool __kill(RDebug *dbg, int pid, int tid, int sig) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return false;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to resume VM\n");
        return false;
    }
    return true;
}

static int __select(int pid, int tid) {
    printf("%s\n", __func__);

}

static RDebugInfo* __info(RDebug *dbg, const char *arg) {
    printf("%s\n", __func__);

}

static RList* __frames(RDebug *dbg, ut64 at) {
    printf("%s\n", __func__);

}

static int __reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status = 0;


    printf("%s, type: %d, size:%d\n", __func__, type, size);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }
    unsigned int nb_vcpus = vmi_get_num_vcpus(rio_vmi->vmi);

    registers_t regs;
    uint64_t cr3 = 0;
    pid_t pid;
    bool found = false;
    for (int vcpu = 0; vcpu < nb_vcpus; vcpu++)
    {
        // get cr3
        status = vmi_get_vcpureg(rio_vmi->vmi, &cr3, CR3, vcpu);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to get vcpu registers\n");
            return 1;
        }
        // convert to pid
        status = vmi_dtb_to_pid(rio_vmi->vmi, cr3, &pid);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to convert CR3 to PID\n");
            return 1;
        }
        if (pid == rio_vmi->pid)
        {
            found = true;

            // get registers
            status = vmi_get_vcpuregs(rio_vmi->vmi, &regs, vcpu);
            if (status == VMI_FAILURE)
            {
                eprintf("Fail to get vcpu registers\n");
                return 1;
            }
            break;
        }
    }
    if (!found)
    {
        eprintf("Cannot find CR3 !\n");
        return 1;
    }

    int arch = r_sys_arch_id (dbg->arch);
    int bits = dbg->anal->bits;

    switch (arch) {
        case R_SYS_ARCH_X86:
            switch (bits) {
                case 32:
                    eprintf("Bits not supported\n");
                    return 1;
                case 64:
                    memcpy(buf      , &(regs.x86.rax), sizeof(regs.x86.rax));
                    memcpy(buf + 8  , &(regs.x86.rbx), sizeof(regs.x86.rbx));
                    memcpy(buf + 16 , &(regs.x86.rcx), sizeof(regs.x86.rcx));
                    memcpy(buf + 24 , &(regs.x86.rdx), sizeof(regs.x86.rdx));
                    memcpy(buf + 128, &(regs.x86.rip), sizeof(regs.x86.rip));
                    break;
            }
            break;
        default:
            eprintf("Architecture not supported\n");
            return 1;
    }
    printf("rip buf[128] %lx\n", *(uint64_t*)(buf + 128));

    return 0;
}

RDebugPlugin r_debug_plugin_vmi = {
    .name = "vmi",
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
    .step = &__step,
    .cont = &__continue,
    .attach = &__attach,
    .detach = &__detach,
    .threads = &__threads,
    .wait = &__wait,
    .map_get = &__map_get,
    .modules_get = &__modules_get,
    .breakpoint = &__breakpoint,
    .reg_profile = (void*) &__reg_profile,
    .kill = &__kill,
    .info = &__info,
    .select = &__select,
    .frames = &__frames,
    .reg_read = &__reg_read,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_DBG,
    .data = &r_debug_plugin_vmi,
    .version = R2_VERSION
};
#endif

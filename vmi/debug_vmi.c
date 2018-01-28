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


// "dc" continue execution
static int __continue(RDebug *dbg, int pid, int tid, int sig) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;

    printf("%s, sig: %d\n", __func__, sig);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status = VMI_FAILURE)
    {
        eprintf("Failed to resume VM execution\n");
        return 1;
    }
    return 0;
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
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status = 0;
    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

}

static RList *__map_get(RDebug* dbg) {
    printf("%s\n", __func__);

}

static RList* __modules_get(RDebug *dbg) {
    printf("%s\n", __func__);

}

static int __breakpoint (void *bp, RBreakpointItem *b, bool set) {
    printf("%s, set: %d\n", __func__, set);

    if (!bp)
        return false;


    if (set)
    {

    } else {

    }

    return true;
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
#include "x86-32.h"
                            );
                            break;
                case 64:
                    return strdup (
#include "x86-64.h"
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

// "dk" send signal
static bool __kill(RDebug *dbg, int pid, int tid, int sig) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    printf("%s, sig: %d\n", __func__, sig);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return false;
    }

    if (sig < 0 || sig > 31)
        return false;
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
    int buf_size = 0;


    // printf("%s, type: %d, size:%d\n", __func__, type, size);

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
                    memcpy(buf + 32 , &(regs.x86.rsi), sizeof(regs.x86.rsi));
                    memcpy(buf + 40 , &(regs.x86.rdi), sizeof(regs.x86.rdi));
                    memcpy(buf + 48 , &(regs.x86.rbp), sizeof(regs.x86.rbp));
                    memcpy(buf + 56 , &(regs.x86.rsp), sizeof(regs.x86.rsp));
                    memcpy(buf + 128, &(regs.x86.rip), sizeof(regs.x86.rip));
                    break;
            }
            break;
        default:
            eprintf("Architecture not supported\n");
            return 1;
    }
    buf_size = 128 + sizeof(uint64_t);

    return buf_size;
}

RDebugPlugin r_debug_plugin_vmi = {
    .name = "vmi",
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
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

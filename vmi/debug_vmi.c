#include <r_asm.h>
#include <r_debug.h>
#include <glib.h>

#include "io_vmi.h"

// vmi_events_listen loop
static bool interrupted = false;

typedef struct {
    pid_t pid;
    registers_t regs;
    status_t status;
    RIOVmi *rio_vmi;
} cr3_load_event_data_t;

//
// callbacks
//
static event_response_t cb_on_sstep(vmi_instance_t vmi, vmi_event_t *event) {
    printf("%s\n", __func__);

    // stop monitoring
    interrupted = true;
    return 0;
}

static event_response_t cb_on_cr3_load(vmi_instance_t vmi, vmi_event_t *event){
    pid_t pid;

    printf("%s\n", __func__);

    if(!event || event->type != VMI_EVENT_REGISTER || !event->data) {
        eprintf("ERROR (%s): invalid event encounted\n", __func__);
        return 0;
    }

    // get event data
    cr3_load_event_data_t event_data = *(cr3_load_event_data_t*)(event->data);

    status_t status = vmi_dtb_to_pid(vmi, (addr_t) event->reg_event.value, &pid);
    if (status == VMI_FAILURE)
    {
        eprintf("ERROR (%s): fail to retrieve pid from cr3\n", __func__);
        return 0;
    }

    printf("Intercepted PID: %d, CR3: 0x%lx\n", pid, event->reg_event.value);
    // check if it's our pid
    if (pid == event_data.pid)
    {
        // stop monitoring
        interrupted = true;
        // pause the VM before we get out of main loop
        status = vmi_pause_vm(vmi);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to pause VM\n");
            return 0;
        }
        // set current VCPU
        event_data.rio_vmi->current_vcpu = event->vcpu_id;
        // save new CR3 value
        event_data.rio_vmi->cr3_attach = event->reg_event.value;
    }

    return 0;
}

static event_response_t cb_on_int3(vmi_instance_t vmi, vmi_event_t *event){
    printf("%s\n", __func__);

    return 0;
}


//
// R2 debug interface
//
static int __step(RDebug *dbg) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;

    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    rio_vmi->wait_event = calloc(1, sizeof(vmi_event_t));
    rio_vmi->wait_event->version = VMI_EVENTS_VERSION;
    rio_vmi->wait_event->type = VMI_EVENT_SINGLESTEP;
    rio_vmi->wait_event->callback = cb_on_sstep;
    rio_vmi->wait_event->ss_event.enable = 1;
    SET_VCPU_SINGLESTEP(rio_vmi->wait_event->ss_event, rio_vmi->current_vcpu);
    status = vmi_register_event(rio_vmi->vmi, rio_vmi->wait_event);
    if (status == VMI_FAILURE)
    {
        eprintf("Failed to register event\n");
        return false;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Failed to resume VM execution\n");
        return 1;
    }

    return true;
}


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

    // register event for int3
    rio_vmi->wait_event = calloc(1, sizeof(vmi_event_t));
    SETUP_INTERRUPT_EVENT(rio_vmi->wait_event, 0, cb_on_int3);

    status = vmi_register_event(rio_vmi->vmi, rio_vmi->wait_event);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to register event\n");
        return 1;
    }

    status = vmi_resume_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Failed to resume VM execution\n");
        return 1;
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
    event_data.rio_vmi = rio_vmi;

    // add it to cr3_load_event
    cr3_load_event.data = (void*)&event_data;

    status = vmi_register_event(rio_vmi->vmi, &cr3_load_event);
    if (status == VMI_FAILURE)
    {
        eprintf("vmi event registration failure\n");
        vmi_resume_vm(rio_vmi->vmi);
        return 1;
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
            return 1;
        }
    }

    // unregister cr3 event
    status = vmi_clear_event(rio_vmi->vmi, &cr3_load_event, NULL);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to clear event\n");
        return 1;
    }

    // set attached to allow reg_read
    rio_vmi->attached = true;

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
    status_t status;
    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    // wait until we have an event
    while (!vmi_are_events_pending(rio_vmi->vmi))
    {
        usleep(1000);
    }

    // pause vm again
    status = vmi_pause_vm(rio_vmi->vmi);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to pause VM\n");
        return false;
    }

    interrupted = false;
    while (!interrupted) {
        printf("Listen to VMI events\n");
        status = vmi_events_listen(rio_vmi->vmi, 1000);
        if (status == VMI_FAILURE)
        {
            eprintf("Fail to listen to events\n");
            return false;
        }
        printf("Listening done\n");
    }

    // clear event
    status = vmi_clear_event(rio_vmi->vmi, rio_vmi->wait_event, NULL);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to clear event\n");
        return false;
    }
    free(rio_vmi->wait_event);

    return 0;
}

// "dm" get memory maps of target process
static RList *__map_get(RDebug* dbg) {
    RIODesc *desc = NULL;
    RIOVmi *rio_vmi = NULL;
    status_t status;
    addr_t dtb = 0;
    char unknown[] = "unknown_";

    printf("%s\n", __func__);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return NULL;
    }

    status = vmi_pid_to_dtb(rio_vmi->vmi, rio_vmi->pid, &dtb);
    if (status == VMI_FAILURE)
    {
        eprintf("Fail to get dtb from pid\n");
        return NULL;
    }

    GSList *va_pages = vmi_get_va_pages(rio_vmi->vmi, dtb);
    if (!va_pages)
    {
        eprintf("Fail to get va pages\n");
        return NULL;
    }

    RList *r_maps = r_list_newf((RListFree) r_debug_map_free);
    GSList *loop = va_pages;
    int nb = 0;
    while (loop)
    {
        page_info_t *page = loop->data;
        char str_nb[20];

        // new map name
        int str_nb_size = sprintf(str_nb, "%d", nb);
        char *map_name = calloc(strlen(unknown) + str_nb_size + 1, 1);
        strncat(map_name, unknown, sizeof(unknown));
        strncat(map_name, str_nb, str_nb_size);
        // build RDebugMap
        addr_t map_start = page->vaddr;
        addr_t map_end = page->vaddr + page->size;
        RDebugMap *r_debug_map = r_debug_map_new (map_name, map_start, map_end, R_IO_READ | R_IO_WRITE | R_IO_EXEC, 0);
        // append
        r_list_append (r_maps, r_debug_map);
        // loop
        loop = loop->next;
        nb +=1;
    }

    // free va_pages
    while (va_pages)
    {
        g_free(va_pages->data);
        va_pages = va_pages->next;
    }
    g_slist_free(va_pages);

    return r_maps;
}

static RList* __modules_get(RDebug *dbg) {
    printf("%s\n", __func__);

    return NULL;
}

static int __breakpoint (void *bp, RBreakpointItem *b, bool set) {
    RBreakpoint* rbreak = NULL;
    printf("%s, set: %d, addr: %llu, hw: %d\n", __func__, set, b->addr, b->hw);

    if (!bp)
        return false;

    if (b->hw)
    {
        eprintf("Hardware breakpoints not available in VMI debugger\n");
        return false;
    }

    rbreak = (RBreakpoint*) bp;

    if (set)
    {
        printf("setting breakpoint\n");
        // write 0xCC
        char int3 = 0xCC;
        bool result = rbreak->iob.write_at(rbreak->iob.io, b->addr, &int3, sizeof(int3));
        if (!result)
        {
            eprintf("Fail to write software breakpoint\n");
            return false;
        }
    } else {
        // write the instruction back
        return false;
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
    pid_t pid;
    uint64_t cr3 = 0;
    registers_t regs;

    printf("%s, type: %d, size:%d\n", __func__, type, size);

    desc = dbg->iob.io->desc;
    rio_vmi = desc->data;
    if (!rio_vmi)
    {
        eprintf("%s: Invalid RIOVmi\n", __func__);
        return 1;
    }

    if (!rio_vmi->attached)
        return 0;

    unsigned int nb_vcpus = vmi_get_num_vcpus(rio_vmi->vmi);

    bool found = false;
    for (int vcpu = 0; vcpu < nb_vcpus; vcpu++)
    {
        // get cr3
        // if we have just attached, we cannot rely on vcpu_reg() since the VCPU
        // state has not been synchronized with the new CR3 value from the attach event
        if (rio_vmi->cr3_attach)
            cr3 = rio_vmi->cr3_attach;
        else
        {
            status = vmi_get_vcpureg(rio_vmi->vmi, &cr3, CR3, vcpu);
            if (status == VMI_FAILURE)
            {
                eprintf("Fail to get vcpu registers\n");
                return 1;
            }
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
    // printf("RIP: %p\n", regs.x86.rip);

    return buf_size;
}

RDebugPlugin r_debug_plugin_vmi = {
    .name = "vmi",
    .license = "LGPL3",
    .arch = "x86",
    .bits = R_SYS_BITS_32 | R_SYS_BITS_64,
    .canstep = 1,
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

#ifndef IO_VMI_H
#define IO_VMI_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <glib.h>

typedef struct {
    char *vm_name;
    int pid;
    uint64_t pid_cr3;
    int current_vcpu;
    vmi_instance_t vmi;
    bool attached;
    vmi_event_t *sstep_event;
    // table [rip] -> [vmi_event_t]
    // event might be int3 or mem_event
    GHashTable *bp_events_table;
} RIOVmi;

#endif // IO_VMI_H

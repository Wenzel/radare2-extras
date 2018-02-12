#ifndef IO_VMI_H
#define IO_VMI_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>

typedef struct {
    char *vm_name;
    int pid;
    int current_vcpu;
    vmi_instance_t vmi;
    bool attached;
    vmi_event_t *wait_event;
    uint64_t cr3_attach;
} RIOVmi;

#endif // IO_VMI_H

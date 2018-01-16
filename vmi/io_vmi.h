#ifndef IO_VMI_H
#define IO_VMI_H

#include <libvmi/libvmi.h>

typedef struct {
    char *vm_name;
    int pid;
    vmi_instance_t vmi;
} RIOVmi;

#endif // IO_VMI_H

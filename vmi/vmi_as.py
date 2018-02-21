from rekall import addrspace
from libvmi import Libvmi

import os
import stat

class VMIAddressSpace(addrspace.BaseAddressSpace):
    """An address space which operates on top of Libvmi's interface."""

    __abstract = False
    __name = "vmi"
    order = 0
    __image = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(base is None, "must be first Address Space")
        self.as_assert(session is not None, "session must be passed")

        domain = filename or (session and session.GetParameter("filename"))
        self.as_assert(domain, "domain name missing")

        super(VMIAddressSpace, self).__init__(base=base,session=session,**kwargs)
        self.vmi = Libvmi(domain)


    def close(self):
        self.vmi.destroy()

    def read(self, offset, size):
        buffer, bytes_read = self.vmi.read_pa(offset, size)
        if size != bytes_read:
            raise RuntimeError('Error while reading physical memory at {}'.format(hex(offset)))
        return buffer

    def write(self, offset, data):
        self.vmi.write_pa(offset, data)

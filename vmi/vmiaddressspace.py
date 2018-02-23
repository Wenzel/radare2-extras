from rekall import addrspace
from libvmi import Libvmi


class VMIAddressSpace(addrspace.BaseAddressSpace):
    """An address space which operates on top of Libvmi's interface."""

    __abstract = False
    __name = "vmi"
    order = 90
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
            raise RuntimeError('Error while reading physical memory at '
                               '{}'.format(hex(offset)))
        return buffer

    def write(self, offset, data):
        self.vmi.write_pa(offset, data)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return 4096 < addr < self.vmi.get_memsize() - 1

    def get_available_addresses(self):
        yield (4096, self.vmi.get_memsize() - 4096)

    def get_mappings(self, start=0, end=2 ** 64):
        yield addrspace.Run(start=0, end=self.vmi.get_memsize(),file_offset=0,
                            address_space=self)
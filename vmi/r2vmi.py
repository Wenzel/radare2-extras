#!/usr/bin/env python3

"""
R2VMI

Usage:
  r2vmi.py <vm_name> <pid>

Options:
  -h --help             Show this screen.
  --version             Show version.
"""

# stdlib
import sys
import logging

# local
from vmi_as import VMIAddressSpace

# 3rd
import r2pipe
from docopt import docopt

from rekall import session
from rekall import plugins


def init_logger():
    logging.basicConfig(level=logging.DEBUG)


def init_rekall(domain):
    s = session.Session(
        autodetect=["rsds"],
        logger=logging.getLogger(),
        autodetect_scan_length=18446744073709551616,
        profile_path=[
            "http://profiles.rekall-forensic.com"
        ])
    s.physical_address_space = VMIAddressSpace(filename=domain, session=s)
    return s

def main(args):
    init_logger()
    vm_name = args['<vm_name>']
    pid = args['<pid>']
    session = init_rekall(vm_name)
    output = session.plugins.pslist()
    logging.info(output)

    # url = 'vmi://{}:{}'.format(vm_name, pid)
    # r2 = r2pipe.open(url, ['-d'])
    # output = r2.cmd("pd 10")
    # logging.info(output)
    # r2.cmd('q!')

if __name__ == '__main__':
    ex = main(docopt(__doc__, version='0.1'))
    sys.exit(ex)

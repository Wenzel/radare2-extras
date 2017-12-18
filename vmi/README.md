# Radare 2 IO VMI plugin

This plugins allow you to debug remote process running in a VM.
It uses `Libvmi` to read and write the process virtual address space.

# Requirements

- `radare2`
- `pkg-config`

# Setup

    $ make
    $ make install

Note: if `pkgconfig` fails, you need to:

    export PKG_CONFIG_PATH=/usr/lib/pkgconfig

# Usage

    $ r2 vmi://win7:5344



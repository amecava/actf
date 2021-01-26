import argparse
import claripy
import angr

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=str)

index = 0
mt = [0] * 624

class switcher():
    @classmethod
    def indirect(cls, args):
        method = getattr(cls, args.binary, lambda: "invalid")
        return method(args)

    @classmethod
    def pnrg(cls, args):
        def mag(value):
            mag_array = [0, 0x9908B0DF]
            return claripy.If((value == 0), claripy.BVV(mag_array[0], 32), claripy.BVV(mag_array[1],32))

        def m_seedRand(seed):
            global index
            global mt
            mt[0] = seed & 0xffffffff
            index = 1
            while index < 0x270:
                mt[index] = (mt[index -1] * 0x17b5) & 0xffffffff
                index = index + 1

        def genRandLong():
            global index
            global mt

            if ((0x26f < index) or (index < 0)):
                if ((0x270 < index) or (index < 0)):
                    m_seedRand(0x1105)

                index = 0
                while index < 0xe3:
                    uVar3 = mt[index + 1]
                    mt[index] = mt[index + 0x18d] ^ claripy.LShR((uVar3 & 0x7fffffff | mt[index] & 0x80000000), 1) ^ mag(uVar3 & 1)
                    index = index + 1

                while index < 0x26f:
                    uVar3 = mt[index + 1]
                    mt[index] = mt[index + -0xe3] ^ claripy.LShR((uVar3 & 0x7fffffff | mt[index] & 0x80000000), 1) ^ mag(uVar3 & 1)
                    index = index + 1

                uVar3 = mt[0]
                mt[0x26f] = mt[0x18c] ^ claripy.LShR((uVar3 & 0x7fffffff | mt[0x26f] & 0x80000000), 1) ^ mag(uVar3 & 1)
                index = 0

            iVar1 = index
            index = iVar1 + 1
            uVar2 = mt[iVar1] ^ claripy.LShR(mt[iVar1], 0xb)
            uVar2 = uVar2 ^ (uVar2 << 7) & 0x9d2c5680
            uVar2 = uVar2 ^ (uVar2 << 0xf) & 0xefc60000
            return uVar2 ^ claripy.LShR(uVar2, 0x12)

        seed = claripy.BVS("seed", 32)

        m_seedRand(seed)

        for _ in range(1000):
            genRandLong()

        leek_sym = genRandLong()

        s = claripy.Solver()
        s.add(leek_sym == 0x74866d33)

        print(s.eval(seed, 1))

    @classmethod
    def prodkey(cls, args):
        p = angr.Project('./prodkey')

        main = 0x00400dfc
        state = p.factory.blank_state(addr=main)     

        simgr = p.factory.simulation_manager(state)

        return1 = (0x400deb)
        return0 = (0x400df2)
        simgr.explore(find=return1, avoid=return0)

        if len(simgr.found) > 0:
            result = simgr.found[0]

            for i in range(3):
                print(result.posix.dumps(i))

switcher.indirect(parser.parse_args())

from functools import reduce
import math


class DefinitionRegister:
    defs_dict = dict()
    defs_list = []
    next_bit = 0

    @staticmethod
    def add_to_defs(assign, data):
        if assign not in DefinitionRegister.defs_dict:
            DefinitionRegister.defs_dict[assign] = []

        DefinitionRegister.defs_dict[assign].append(data)

        return DefinitionRegister.defs_dict[assign]

    @staticmethod
    def get_gen_kill(node, assign):
        gen_bit = 1 << DefinitionRegister.next_bit

        DefinitionRegister.defs_list.append(node)
        d = DefinitionRegister.add_to_defs(assign, (gen_bit, node))

        kill_bits = reduce(lambda x, y: x | y, [bit for bit, _ in d])
        kill_bits &= ~gen_bit

        DefinitionRegister.next_bit += 1

        return gen_bit, kill_bits

    @staticmethod
    def get_def_bit(bit):
        return DefinitionRegister.defs_list[int(math.log(bit, 2))]

    @staticmethod
    def get_def_int(i):
        return DefinitionRegister.defs_list[i]

    @staticmethod
    def get_def_bitmask(assign_vars):
        bitmask = 0

        for assign in assign_vars:
            if assign not in DefinitionRegister.defs_dict:
                continue

            for gen_bit, _ in DefinitionRegister.defs_dict[assign]:
                bitmask |= gen_bit

        return bitmask

    @staticmethod
    def reset():
        DefinitionRegister.defs_dict = dict()
        DefinitionRegister.defs_list = []
        DefinitionRegister.next_bit = 0



# typedef int(*dmi_random_t)(int*, int);

from binaryninja import *

def create(bv):
    consts = set()
    for function in bv.functions:
        for const in get_consts_from_function(bv, function):
            consts.add(const)

    print_dict_from(consts, bv.arch.address_size*4)

def get_consts_from_function(bv, func):
    consts = set()
    for basicblock in func.medium_level_il:
        for instruction in basicblock:
            if instruction.operation == MediumLevelILOperation.MLIL_IF:
                for operand in instruction.operands[0].operands:
                    try:
                        if operand.operation == MediumLevelILOperation.MLIL_CONST:
                            consts.add(operand.value.value)
                    except Exception as e:
                        continue
                        #print(e)
                        #print(instruction)
    return consts

def create_for_function(bv, func):
    consts = get_consts_from_function(bv, func)
    print_dict_from(consts, bv.arch.address_size*4)

def print_dict_from(consts, bitsize=32):
    print("#begin dictionary:"+"="*40)
    for idx, const in enumerate(consts):
        if bitsize == 16:
            print("kw{}=\"\\x{:>04x}\"".format(idx, const))
        elif bitsize == 32:
            print("kw{}=\"\\x{:>08x}\"".format(idx, const))
        elif bitsize == 64:
            print("kw{}=\"\\x{:>016x}\"".format(idx, const))
        else:
            raise Exception("Unsupported bitsize: %d" % bitsize)
    print("#end dictionary"+"="*43)

PluginCommand.register("Create dictionary", "Attempt to create a fuzzing dictionary out of constants in the program", create)
PluginCommand.register_for_function("Create dictionary for function", "Attempt to create a fuzzing dictionary out of constants for this function", create_for_function)

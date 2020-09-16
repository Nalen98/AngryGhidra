import sys
import angr
import claripy
import json
import time

EXPLORE_OPT = {}  # Explore options
REGISTERS = []  # Main registers of your binary
SYMVECTORS = []


def hook_function(state):
    for object in EXPLORE_OPT["Hooks"]:
        for frame in object.items():
            if frame[0] == str(hex(state.solver.eval(state.regs.ip))):
                for option, data in frame[1].items():
                    if "sv" in data:
                        symbvector_length = int(data[2:], 0)
                        symbvector = claripy.BVS('symvector', symbvector_length * 8)
                        SYMVECTORS.append(symbvector)
                        data = symbvector
                    else:
                        data = int(str(data), 0)
                    for REG in REGISTERS:
                        if REG == option:
                            setattr(state.regs, option, data)
                            break


def main(file):
    with open(file, encoding='utf-8') as json_file:
        global EXPLORE_OPT
        EXPLORE_OPT = json.load(json_file)

    # Options parser
    # JSON can't handle with hex values, so we need to do it manually
    if "blank_state" in EXPLORE_OPT:
        blank_state = int(EXPLORE_OPT["blank_state"], 16)

    find = int(EXPLORE_OPT["find"], 16)

    if "avoid" in EXPLORE_OPT:
        avoid = [int(x, 16) for x in EXPLORE_OPT["avoid"].split(',')]

    # User can input hex or decimal value (argv length / symbolic memory length)
    argv = [EXPLORE_OPT["binary_file"]]
    if "Arguments" in EXPLORE_OPT:
        index = 1
        for arg, length in EXPLORE_OPT["Arguments"].items():
            argv.append(claripy.BVS("argv" + str(index), int(str(length), 0) * 8))
            index += 1
            
    if "Raw Binary" in EXPLORE_OPT:
        for bin_option, data in EXPLORE_OPT["Raw Binary"].items():
            if bin_option == "Arch":
                arch = data
            if bin_option == "Base":
                base_address = int(str(data), 0)
        p = angr.Project(EXPLORE_OPT["binary_file"],
                         load_options={'main_opts': {'backend': 'blob', 'arch': arch,
                                                     'base_addr': base_address}, 'auto_load_libs': EXPLORE_OPT["auto_load_libs"]})
    else:
        p = angr.Project(EXPLORE_OPT["binary_file"], load_options={"auto_load_libs": EXPLORE_OPT["auto_load_libs"]})

    global REGISTERS
    REGISTERS = p.arch.default_symbolic_registers

    if len(argv) > 1:
        state = p.factory.entry_state(args=argv)
    elif "blank_state" in locals():
        state = p.factory.blank_state(addr=blank_state)
    else:
        state = p.factory.entry_state()

    # Store symbolic vectors in memory
    if "Memory" in EXPLORE_OPT:
        Memory = {}
        for addr, length in EXPLORE_OPT["Memory"].items():
            symbmem_addr = int(addr, 16)
            symbmem_len = int(length, 0)
            Memory.update({symbmem_addr: symbmem_len})
            symb_vector = claripy.BVS('input', symbmem_len * 8)
            state.memory.store(symbmem_addr, symb_vector)

    # Write to memory
    if "Store" in EXPLORE_OPT:
        for addr, value in EXPLORE_OPT["Store"].items():
            store_addr = int(addr, 16)
            store_value = int(value, 16)
            store_length = len(value) - 2
            state.memory.store(store_addr, state.solver.BVV(store_value, 4 * store_length))

    # Handle Symbolic Registers
    if "Registers" in EXPLORE_OPT:
        for register, data in EXPLORE_OPT["Registers"].items():
            if "sv" in data:
                symbvector_length = int(data[2:], 0)
                symbvector = claripy.BVS('symvector', symbvector_length * 8)
                SYMVECTORS.append(symbvector)
                data = symbvector
            else:
                data = int(str(data), 0)
            for REG in REGISTERS:
                if REG == register:
                    setattr(state.regs, register, data)
                    break

    # Handle Hooks
    if "Hooks" in EXPLORE_OPT:
        for object in EXPLORE_OPT["Hooks"]:
            for frame in object.items():
                hook_address = frame[0]
                for option, data in frame[1].items():
                    data = int(str(data), 0)
                    if option == "Length":
                        hook_length = data
                        break
                p.hook(int(hook_address, 16), hook_function, length=hook_length)

    simgr = p.factory.simulation_manager(state)
    if "avoid" in locals():
        simgr.use_technique(angr.exploration_techniques.Explorer(find=find, avoid=avoid))
    else:
        simgr.use_technique(angr.exploration_techniques.Explorer(find=find))

    simgr.run()

    if simgr.found:
        found_path = simgr.found[0]

        win_sequence = ""
        for win_block in found_path.history.bbl_addrs.hardcopy:
            win_block = p.factory.block(win_block)
            addresses = win_block.instruction_addrs
            for address in addresses:
                win_sequence += hex(address) + ","
        win_sequence = win_sequence[:-1]
        print("Trace:" + win_sequence)

        if len(argv) > 1:
            for i in range(1, len(argv)):
                print("argv[{id}] = {solution}".format(id=i, solution=found_path.solver.eval(argv[i], cast_to=bytes)))

        if "Memory" in locals() and len(Memory) != 0:
            for address, length in Memory.items():
                print("{addr} = {value}".format(addr=hex(address),
                                                value=found_path.solver.eval(found_path.memory.load(address, length),
                                                                             cast_to=bytes)))

        if len(SYMVECTORS) > 0:
            for SV in SYMVECTORS:
                print(found_path.solver.eval(SV, cast_to=bytes))

        found_stdins = found_path.posix.stdin.content
        if len(found_stdins) > 0:
            std_id = 1
            for stdin in found_stdins:
                print(
                    "stdin[{id}] = {solution}".format(id=std_id,
                                                      solution=found_path.solver.eval(stdin[0], cast_to=bytes)))
                std_id += 1
    else:
        print("")
    return


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: *thisScript.py* angr_options.json")
        exit()
    file = sys.argv[1]
    main(file)

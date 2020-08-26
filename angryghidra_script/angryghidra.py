import sys
import angr
import claripy
import json
import time

EXPLORE_OPT = {}  #Explore options
REGISTERS = [] #Main registers of your binary


def main(file):

    with open(file) as json_file:
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

    if EXPLORE_OPT["auto_load_libs"] is True:
        p = angr.Project(EXPLORE_OPT["binary_file"], load_options={"auto_load_libs": True})
    else:
        p = angr.Project(EXPLORE_OPT["binary_file"], load_options={"auto_load_libs": False})

    global REGISTERS
    REGISTERS = p.arch.default_symbolic_registers

    if len(argv) > 1:
        state = p.factory.entry_state(args=argv)
    elif "blank_state" in locals():
        state = p.factory.blank_state(addr=blank_state)
    else:
        state = p.factory.entry_state()

# Memory spaces to set
    if "Memory" in EXPLORE_OPT:
        Memory = {}
        for addr, length in EXPLORE_OPT["Memory"].items():
            symbmem_addr = int(addr, 16)
            symbmem_len = int(length, 0)
            Memory.update({symbmem_addr: symbmem_len})
            symb_vector = claripy.BVS('input', symbmem_len * 8)
            state.memory.store(symbmem_addr, symb_vector)

# Handle Symbolic Registers (if you know actually which registers are necessary to store your data)
    if "Registers" in EXPLORE_OPT:
        for register, data in EXPLORE_OPT["Registers"].items():
            data = int(str(data), 0)
            for REG in REGISTERS:
                if REG == register:
                    setattr(state.regs, register, data)
                    break

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

        #If argv was used
        if len(argv) > 1:
            for i in range(1, len(argv)):
                print("argv[{id}] = {solution}".format(id=i, solution=found_path.solver.eval(argv[i], cast_to=bytes)))

        # Print value from user's memory space set
        if "Memory" in locals() and len(Memory) != 0:
            for address, length in Memory.items():
                print("{addr} = {value}".format(addr=hex(address), value=found_path.solver.eval(found_path.memory.load(address, length), cast_to=bytes)))

        # STDIN
        found_stdins = found_path.posix.stdin.content
        if len(found_stdins) > 0:
            std_id = 1
            for stdin in found_stdins:
                print(
                    "stdin[{id}] = {solution}".format(id=std_id, solution=found_path.solver.eval(stdin[0], cast_to=bytes)))
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

#!/usr/bin/python3

from capstone import *
from termcolor import colored
from elftools.elf.elffile import ELFFile
import subprocess
import os
from pydbg import *
from pydbg.defines import *
import struct
import random

binary = "binary"
location = "0x000000"
functions = {}
CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
file = ""
jumps = {}
jmp_instructions = ["je", "jb", "jl", "jge", "jle", "jmp", "jne", "jbe"]
md = Cs(CS_ARCH_X86, CS_MODE_64)

instructions = []
visited = []

dbg = pydbg()

def main():
    global pydbg
    print("Reading file: " + binary)

    with open(binary, "rb") as f:
        elffile = ELFFile(f)
        code = elffile.get_section_by_name(".text")
        opcodes = code.data()

        read_instructions(code['sh_addr'], opcodes)

        print("Auto analyzing file...")
        analyze()

        while True:
            print("[" + location + "]> ", end = '', flush = True)
            command = input().split(" ")

            if command[0] == "a":
                analyze()
            elif command[0] == "d":
                dissasemble2(code['sh_addr'], opcodes)
            elif command[0] == "afl":
                print_functions()
            elif command[0] == "clear":
                os.system("clear")

            elif command[0] == "p":
                print("p:   print ?")
                print("pd:  print disassembly")
                print("pds: print disassembly summary")
                print("pdf: print disassembly function")
                print("pdfs: print disassembly function summary")
            elif command[0] == "pd":
                print_disassembly()
            elif command[0] == "pdr":
                print_disassembly_recursive()
            elif command[0] == "pds":
                print_disassembly_summary()
            elif command[0] == "pdf":
                print_disassembly_function()
            elif command[0] == "pdfs":
                print_disassembly_function_summary()

            elif command[0] == "i":
                print("i:   info ?")
                print("is:  info sections")
                print("if:  info functions")
            elif command[0] == "is":
                header()
            elif command[0] == "if":
                print_functions()


            elif command[0] == "s":
                seek(command[1])
            elif command[0] == "q":
                exit()
            elif command[0] == "ood":
                if len(command) != 2:
                    print("Usage: ood <pid>")
                else:
                    dbg.attach(int(command[1]))
            elif command[0] == "db":
                if len(command) != 2:
                    print("Usage: db <address>")
                else:
                    dbg.bp_set(int(command[1], 16), description="Breakpoint", handler=hit_breakpoint)

def hit_breakpoint():
    print("Hit the breakpoint")
                

def print_disassembly_recursive():
    global program
    global location

    print("Starting recursive disassembly from location...")

    pdr(location)


def pdr(loc):
    global program
    global visited
    found_start = False

    for i in instructions:
        if i.address == loc:
            found_start = True
        if found_start == True:
            print_instruction(i)
            visited.append(i.address)
            if i.instruction == "call" and not i.opcode in visited:
                print("[" + i.opcode + "] (Called)")
                pdr(i.opcode)
            if i.instruction[0] == "j" and not i.opcode in visited:
                print("[" + i.opcode + "] (Jumped)")
                pdr(i.opcode)
            if i.instruction == "ret":
                return


def line():
    print("=" * 80)

def print_functions():
    global functions

    for f in functions.keys():
        print(f + " " + functions[f])

def header():
    with open(binary, "rb") as f:
        elffile = ELFFile(f)
        #result = result.stdout.decode('utf-8')
        for section in elffile.iter_sections():
            print(section.name)

def read_instructions(addr, opcodes):
    global instructions

    for i in md.disasm(opcodes, addr):
        i = Ins("0x%x" % i.address, i.mnemonic, i.op_str)
        instructions.append(i)

def seek(loc):
    global location
    global functions

    for f in functions:
        if functions[f] == loc:
            location = f

def print_instruction(i):
    if i.instruction == "ret":
        print(colored(i, "red"))
    elif i.instruction in jmp_instructions:
        print(colored(i, "green"))
    elif i.instruction == "call":
        print(colored(i, "yellow"))
    else: print(i)

def print_disassembly():
    global program

    for i in instructions:
        print_instruction(i)

def print_disassembly_summary():
    global program

    for i in instructions:
        if i.instruction == "call":
            print_instruction(i)

def print_disassembly_function():
    global program
    found_start = False

    for i in instructions:
        if i.address == location:
            found_start = True
        if found_start == True:
            print_instruction(i)
            if i.instruction == "ret":
                return

def print_disassembly_function_summary():
    global program
    found_start = False

    for i in instructions:
        if i.address == location:
            found_start = True
        if found_start == True:
            if i.instruction == "call":
                print_instruction(i)
            if i.instruction == "ret":
                return

def analyze():
    global instructions
    global functions

    global location
    location = "0x4008d6"

    temp_references = {}
    reference_count = 0

    function_str = str(subprocess.run(["nm", "--demangle", binary], stdout=subprocess.PIPE)).split("\\n")
    for f in function_str:
        if " T " in f:
            func = f.split(" ")
            func[0] = "0x" + func[0].lstrip("0")
            functions[func[0]] = func[2]
            #print(func[0] + " " + func[2])
    print("Found " + str(len(functions)) + " functions")

    for i in instructions:
        if i.instruction in jmp_instructions:
            reference_count = reference_count + 1

            temp_references[i.opcode] = i.address

    print("Found " + str(reference_count) + " references")

    for i in instructions:
        if i.address in temp_references.keys():
            i.add_reference(temp_references[i.address])
        if i.address in functions.keys():
            i.is_function = True
            i.function_name = functions[i.address]




class Ins:
    def __init__(self, address, instruction, opcode):
        self.address = address
        self.instruction = instruction
        self.opcode = opcode
        self.references = []
        self.is_function = False
        self.function_name = ""

    def __str__(self):
        ret_str = ""
        ref_str = ""

        if self.is_function:
            ret_str += "\n" + self.function_name + ":\n"

        if len(self.references) > 0:
            ref_str = "# Referenced from: "

        for r in self.references:
            ref_str = ref_str + r

        ret_str += "\t" + self.address + "\t" + self.instruction + "\t" + self.opcode + "\t" + ref_str
        return ret_str

    def add_reference(self, reference):
        self.references.append(reference)

main()

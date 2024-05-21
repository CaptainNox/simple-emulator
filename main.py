#!/bin/python3
from capstone import *
from capstone.x86 import *

# Implementation of x86 CPU registers
registers = {}
registers[X86_REG_EAX] = 0
registers[X86_REG_EBX] = 0

# Implementation for the CPU instruction pointer
registers[X86_REG_EIP] = 0

# Reading bytes of binary
code = ""
with open("shellcode/add.bin", "rb") as bin:
    code = bin.read()

# Setting up capstone
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True

# Iterate through all instructions
while registers[X86_REG_EIP] != len(code):
    addr = registers[X86_REG_EIP]
    instruction = next(cs.disasm(code[addr:addr + 15], addr))
    print(f"Instruction ({addr}): {instruction.mnemonic}")

    # Incrementing EIP
    registers[X86_REG_EIP] += instruction.size

print("Done, iterated through all instructions")


#!/bin/python3
from capstone import *
from capstone.x86 import *

# Implementation of x86 CPU registers
registers = {}
registers[X86_REG_EAX] = 0
registers[X86_REG_EBX] = 0

# Implementation for the CPU instruction pointer
registers[X86_REG_EIP] = 0

# Setting up capstone
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True

def mov_impl(operands):
    if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
        registers[operands[0].reg] = operands[1].value.imm
    else:
        print("This type of MOV is not implemented yet!")

def add_impl(operands):
    if operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
        registers[operands[0].reg] = registers[operands[0].reg] + registers[operands[1].reg]
    else:
        print("This variant of ADD is not implemented yet!")

# Instruction handling implementation using dictionary to have O(1) access time
instructions = {
        "mov": mov_impl,
        "add": add_impl
}

# Reading bytes of binary
code = ""
with open("shellcode/add.bin", "rb") as bin:
    code = bin.read()

# Iterate through all instructions
while registers[X86_REG_EIP] != len(code):
    addr = registers[X86_REG_EIP]
    instruction = next(cs.disasm(code[addr:addr + 15], addr))

    if instruction.mnemonic in instructions:
        instructions[instruction.mnemonic](instruction.operands) # Calling the implementation of the instruction

    else:
        print(f"Instruction {instruction.mnemonic} not implemented")

    # Incrementing EIP
    registers[X86_REG_EIP] += instruction.size


print(f"Done, result of EAX: {registers[X86_REG_EAX]}")
print(f"Done, result of EBX: {registers[X86_REG_EBX]}")


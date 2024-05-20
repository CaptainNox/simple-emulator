#!/bin/python3

from capstone import *
from capstone.x86 import *

instructions = ""
with open("shellcode/add.bin", "rb") as bin:
    instructions = bin.read()

print(instructions)

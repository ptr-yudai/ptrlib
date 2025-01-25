#!/usr/bin/env python3
import requests
import re

def syscall_table(arch, bits):
    table = {}
    r = requests.get(URL.format(arch=arch, bits=bits))
    for num, _, name in re.findall(r"(\d+).+(common|64|i386).+\ssys_([a-z0-9_]+)", r.text):
        table[name] = int(num)
    return table

def syscall_table_arm64():
    # WTF
    table = {}
    r = requests.get(URL)
    for name, num in re.findall(r"#define\s+__NR_([a-z0-9_]+)\s+(\d+)", r.text):
        table[name] = int(num)
    return table

if __name__ == '__main__':
    URL = "https://raw.githubusercontent.com/torvalds/linux/master/arch/{arch}/entry/syscalls/syscall_{bits}.tbl"
    #print(syscall_table("x86", 32))
    #print(syscall_table("x86", 64))

    URL = "https://raw.githubusercontent.com/torvalds/linux/master/arch/{arch}/tools/syscall.tbl"
    #print(syscall_table("arm", 32))

    URL = "https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h"
    print(syscall_table_arm64())

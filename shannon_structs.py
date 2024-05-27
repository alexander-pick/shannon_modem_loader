#!/bin/python3

# Samsung Shannon Modem Loader, Structs
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

import idaapi
import ida_struct
import ida_nalt

# ARM scatter structure
def add_scatter_struct():

    struct_id = ida_struct.add_struc(0, "scatter", 0)
    sptr = ida_struct.get_struc(struct_id)
    mt = ida_nalt.opinfo_t()

    ida_struct.add_struc_member(sptr, "src", -1, idaapi.FF_DATA |
                         idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    ida_struct.add_struc_member(sptr, "dst", -1, idaapi.FF_DATA |
                         idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    ida_struct.add_struc_member(sptr, "size", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "op", -1, idaapi.FF_DATA |
                         idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    
# debug trace structure
def add_dbt_struct():

    # DBT entries with file and string ref
    struct_id = ida_struct.add_struc(0, "dbg_trace", 0)
    sptr = ida_struct.get_struc(struct_id)
    mt = ida_nalt.opinfo_t()

    ida_struct.add_struc_member(sptr, "head", -1, idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "group", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "channel", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "num_param", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "msg_ptr", -1, idaapi.FF_DATA |
                         idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    ida_struct.add_struc_member(sptr, "line", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "file", -1, idaapi.FF_DWORD, mt, 4)

# MPU table structure
def add_mpu_region_struct():

    struct_id = ida_struct.add_struc(0, "mpu_region", 0)
    sptr = ida_struct.get_struc(struct_id)
    mt = ida_nalt.opinfo_t()

    ida_struct.add_struc_member(sptr, "num", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "addr", -1, idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    ida_struct.add_struc_member(sptr, "size", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "tex", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # Type Extension (TEX)
    ida_struct.add_struc_member(sptr, "ap", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # Data access permission
    ida_struct.add_struc_member(sptr, "xn", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # Execute never
    ida_struct.add_struc_member(sptr, "se", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # Shareable (S)
    ida_struct.add_struc_member(sptr, "ce", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # Cacheable (C)
    ida_struct.add_struc_member(sptr, "be", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # Bufferable (B)
    ida_struct.add_struc_member(sptr, "en", -1, idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4) # enabled

# Task Structure
def add_task_struct():
    
    struct_id = ida_struct.add_struc(0, "task_struct", 0)
    sptr = ida_struct.get_struc(struct_id)
    mt = ida_nalt.opinfo_t()

    ida_struct.add_struc_member(sptr, "gap_0", -1, idaapi.FF_BYTE, mt, 8)
    ida_struct.add_struc_member(sptr, "state", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "flag", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_1", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_2", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "task_num", -1, idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "stack", -1, idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "gap_3", -1, idaapi.FF_BYTE, mt, 0x10)
    ida_struct.add_struc_member(sptr, "task_name", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    ida_struct.add_struc_member(sptr, "priority", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_4", -1, idaapi.FF_BYTE, mt, 3)
    ida_struct.add_struc_member(sptr, "stack_size", -1, idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "task_entry", -1,
                         idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    ida_struct.add_struc_member(sptr, "task_init", -1, idaapi.FF_DWORD, mt, 4)
    ida_struct.add_struc_member(sptr, "gap_5", -1, idaapi.FF_BYTE, mt, 4)
    ida_struct.add_struc_member(sptr, "gap_6", -1, idaapi.FF_BYTE, mt, 0x24)
    ida_struct.add_struc_member(sptr, "gap_7", -1, idaapi.FF_BYTE, mt, 0x28)
    ida_struct.add_struc_member(sptr, "gap_8", -1, idaapi.FF_BYTE, mt, 0x78)
    ida_struct.add_struc_member(sptr, "gap_9", -1, idaapi.FF_BYTE, mt, 4)
    ida_struct.add_struc_member(sptr, "gap_10", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_11", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_12", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_13", -1, idaapi.FF_BYTE, mt, 1)
    ida_struct.add_struc_member(sptr, "gap_14", -1, idaapi.FF_BYTE, mt, 16)
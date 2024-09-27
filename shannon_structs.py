#!/bin/python3

# Samsung Shannon Modem Loader - Structs
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

import idaapi
import ida_nalt
import idc
import ida_typeinf

import shannon_generic

# IDA 9.0 requires some new code to work with structs as these API were removed

# get struct by id
def get_struct(tid):
    # this is super ugly but I have no better solution at the moment since get_type_by_tid
    # does not exist in 8.3 yet so we need to use ida_struct for backwards compatibility
    if(idaapi.IDA_SDK_VERSION < 900):
        try:
            return __import__("ida_struct").get_struc(tid)
        except:
            idc.msg("[e] failed to import legacy ida_struct\n")
            return None
    else:
        tif = None

        tif = ida_typeinf.tinfo_t()
        tif.get_type_by_tid(tid)

        if (tif):
            if (tif.is_struct()):
                return tif
            else:
                idc.msg("[e] get_struct(): is no struct\n")

        idc.msg("[e] get_struct(): failed to get struct\n")

        return idaapi.BADADDR

# get member by name
def get_member_by_name(tif, name):
    if(idaapi.IDA_SDK_VERSION < 900):
        return __import__("ida_struct").get_member_by_name(tif, name)
    else:
        if (tif):
            if (not tif.is_struct()):
                idc.msg("[e] get_member_by_name(tif, %s): tif is not a struct\n" % name)
                return None
        else:
            idc.msg("[e] get_member_by_name(tif, %s): tif is not defined\n" % name)

        udm = ida_typeinf.udm_t()
        udm.name = name
        idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
        if (idx != -1):
            shannon_generic.DEBUG("[d] get_member_by_name(%s) idx: %x\n" % (name, idx))
            return udm
        
        idc.msg("[e] get_member_by_name(tif, %s) connot find member in struct\n" % name)
        return None

# get offset of member by name
# offset needs to be devided by 8 for some reason
def get_offset_by_name(tif, name):
    member = get_member_by_name(tif, name)
    if (member):
        if(idaapi.IDA_SDK_VERSION < 900):
            return (member.soff)
        else:
            shannon_generic.DEBUG("[d] get_offset_by_name(%s): %x\n" % (name, member.offset))
            if(member.offset == 0):
                return 0
            return (member.offset // 8)
    idc.msg("[e] get_offset_by_name(tif, %s): cannot get offset\n" % name)
    return None

# get_max_offset to maintain
# finds the end of the struct to append to
def get_max_offset(tif):
    if(idaapi.IDA_SDK_VERSION < 900):
        return __import__("ida_struct").get_max_offset(tif)
    else:
        if (tif):
            if (tif.is_struct()):
                return tif.get_size()
            elif (tif.is_union()):
                return tif.get_udt_nmembers()
        else:
            idc.msg("[e] get_max_offset(): tif is invalid\n")

        idc.msg("[e] get_max_offset(): connot get max offset\n")
        return -1

# replacement for add_struc_member during IDA9 porting, kept for debugging
def add_struc_member(tid, name, offset, flag, typeid, nbytes):
    #shannon_generic.DEBUG("[d] add_struc_member(tid, %s, %x, %x, %x, %d) \n" % (name, offset, flag, typeid, nbytes))
    # if(idaapi.IDA_SDK_VERSION >= 900):
    idc.add_struc_member(tid, name, offset, flag, typeid, nbytes)
    # else:
    #     tif = get_struct(tid)
    #     if(tif):
    #         sid = idc.get_struc_id(tif.name)
    #         idc.add_struc_member(sid, name, offset, flag, typeid, nbytes)
    #         return
    #     else:
    #         idc.msg("[e] add_struc_member(): connot add member, unknown tif\n")

# ARM scatter structure
def add_scatter_struct():

    tid = idc.add_struc(0, "scatter", 0)
    mt = -1

    add_struc_member(tid, "src", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    add_struc_member(tid, "dst", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    add_struc_member(tid, "size", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "op", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)

# debug trace structure
def add_dbt_struct():

    # DBT entries with file and string ref
    tid = idc.add_struc(0, "dbg_trace", 0)
    mt = -1

    add_struc_member(tid, "head", -1,
                     idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "group", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "channel", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "num_param", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "msg_ptr", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD | idaapi.FF_0OFF, ida_nalt.STRTYPE_C, 4)
    add_struc_member(tid, "line", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "file", -1,
                     idaapi.FF_DWORD, mt, 4)

# MPU table structure
def add_mpu_region_struct():

    tid = idc.add_struc(0, "mpu_region", 0)
    mt = -1

    add_struc_member(tid, "num", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "addr", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    add_struc_member(tid, "size", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "tex", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # Type Extension (TEX)
    add_struc_member(tid, "ap", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # Data access permission
    add_struc_member(tid, "xn", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # Execute never
    add_struc_member(tid, "se", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # Shareable (S)
    add_struc_member(tid, "ce", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # Cacheable (C)
    add_struc_member(tid, "be", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # Bufferable (B)
    add_struc_member(tid, "en", -1, idaapi.FF_DATA |
                     idaapi.FF_DWORD, mt, 4)  # enabled

# Task Structure
def add_task_struct():

    tid = idc.add_struc(0, "task_struct", 0)
    mt = -1

    add_struc_member(tid, "gap_0", -1,
                     idaapi.FF_BYTE, mt, 8)
    add_struc_member(tid, "state", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "flag", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "gap_1", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "gap_2", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "task_num", -1,
                     idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "stack", -1,
                     idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "gap_3", -1,
                     idaapi.FF_BYTE, mt, 0x10)
    add_struc_member(tid, "task_name", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, ida_nalt.STRTYPE_C, 4)
    add_struc_member(tid, "priority", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "gap_4", -1,
                     idaapi.FF_BYTE, mt, 3)
    add_struc_member(tid, "stack_size", -1,
                     idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "task_entry", -1,
                     idaapi.FF_DATA | idaapi.FF_DWORD | idaapi.FF_0OFF, mt, 4)
    add_struc_member(tid, "task_init", -1,
                     idaapi.FF_DWORD, mt, 4)
    add_struc_member(tid, "gap_5", -1,
                     idaapi.FF_BYTE, mt, 4)
    add_struc_member(tid, "gap_6", -1,
                     idaapi.FF_BYTE, mt, 0x24)
    add_struc_member(tid, "gap_7", -1,
                     idaapi.FF_BYTE, mt, 0x28)
    add_struc_member(tid, "gap_8", -1,
                     idaapi.FF_BYTE, mt, 0x78)
    add_struc_member(tid, "gap_9", -1,
                     idaapi.FF_BYTE, mt, 4)
    add_struc_member(tid, "gap_10", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "gap_11", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "gap_12", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "gap_13", -1,
                     idaapi.FF_BYTE, mt, 1)
    add_struc_member(tid, "padding", -1,
                     idaapi.FF_BYTE, mt, 16)

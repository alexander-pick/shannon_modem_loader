#!/bin/python3

# Samsung Shannon Modem Loader, Generic Functions
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

import idc
import idaapi
import ida_segment
import ida_bytes
import ida_ua
import ida_name
import idautils

# adds a memory segment to the database
def add_memory_segment(seg_start, seg_size, seg_name, seg_type="DATA", sparse=True):

    seg_end = seg_start + seg_size

    idc.add_segm_ex(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes,
                    idaapi.scPub, ida_segment.ADDSEG_SPARSE)

    idc.set_segm_class(seg_start, seg_type)
    idc.set_segm_type(seg_start, idaapi.SEG_DATA)
    idc.set_segm_name(seg_start, seg_name)

    # make sure it is really STT_MM (sparse)
    if (sparse):
        ida_bytes.change_storage_type(seg_start, seg_end, 1)

# create a name at offset an validate if the name exists already
def create_name(ea, name):
    for xref in idautils.XrefsTo(ea, 0):
        func_start = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)

        if (func_start != idaapi.BADADDR):
            if (len(name) > 8):
                ida_name.set_name(func_start, function_find_name(
                    name), ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            else:
                idc.msg("[e] %x: function name too short: %s\n" %
                        (func_start, name))

# helper function to set a name on the target of a LDR or B
def get_ref_set_name(cur_ea, name):

    opcode = ida_ua.ua_mnem(cur_ea)
    # idc.msg("[d] %x: %s -> %s\n" % (cur_ea, opcode, name))
    if (opcode == "LDR"):
        target_ref = idc.get_operand_value(cur_ea, 1)
        target = int.from_bytes(
            ida_bytes.get_bytes(target_ref, 4), "little")
        ida_name.set_name(target, name, ida_name.SN_NOCHECK)
    if (opcode == "B"):
        target = idc.get_operand_value(cur_ea, 0)
        ida_name.set_name(target, name, ida_name.SN_NOCHECK)

# check if name exists already inside the idb
def function_exists(name):

    for addr in idautils.Functions():

        func_name = idc.get_func_name(addr)

        if func_name == name:
            return True

    return False

# deal with dupes in some modems
def function_find_name(name):

    postfix = 0
    orig_name = name

    while (function_exists(name) == True):
        if (postfix > 0):
            name = orig_name + "_" + str(postfix)
        postfix += 1
        # sanity check
        if (postfix > 42):
            break

    # filter some bad chars before returning the string
    return name.translate(dict.fromkeys(map(ord, u",~")))

# resovles a string reference from offset
def resolve_ref(str_addr):

    name = None
    str_offset = int.from_bytes(ida_bytes.get_bytes(str_addr, 4), "little")
    # idc.msg("[d] %x: fallback ref\n" % str_offset)

    name = idc.get_strlit_contents(str_offset)
    # yes it's a ref to a string

    if (name != None):
        return name
    else:
        return None
    
# I am using some metrics of the function for analysis instead of pattern since
# we have a limited number of candidates and highly optimized code which will
# most likely keep it's functional characteristics over time

def get_metric(bl_target):

    loops = []
    branch = []
    ldr = []

    length = 0

    func_start = idc.get_func_attr(bl_target, idc.FUNCATTR_START)
    func_end = idc.get_func_attr(bl_target, idc.FUNCATTR_END)

    func_cur = bl_target

    if (func_end != idaapi.BADADDR):

        while (func_cur < func_end):

            length += 1

            func_cur = idc.next_head(func_cur)

            opcode = ida_ua.ua_mnem(func_cur)

            # bailout
            if (opcode == None):
                # idc.msg("[d] no opcode at %x\n" % func_cur)
                continue

            if ("BL" in opcode):

                first_operand = idc.get_operand_value(func_cur, 0)

                # sometimes the boundary calculated by IDA is a bit off if firmware
                # contains DCD references at the end of the function
                if (first_operand == "LR"):
                    break

                # idc.msg("[d] BL@%x -> %x\n" % (func_cur, first_operand))

                if (first_operand >= func_start and func_cur > first_operand):
                    # jump backwards inside function, most likely a loop
                    loops.append(first_operand)
                else:
                    branch.append(first_operand)

            if ("LDR" in opcode):
                ldr.append(idc.get_operand_value(func_cur, 1))

    # get basic block count of function
    function = idaapi.get_func(func_start)
    flow_chart = idaapi.FlowChart(function)

    xrefs = list(idautils.XrefsTo(func_start, 0))

    return [loops, branch, length, flow_chart.size, xrefs, ldr]
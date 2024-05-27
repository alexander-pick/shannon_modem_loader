#!/bin/python3

# Samsung Shannon Modem Scatter Load Processor
# This script is autoamtically executed by the loader
# Alexander Pick 2024

import idc
import idaapi
import ida_ua
import ida_idp
import ida_bytes
import idautils
import ida_name
import ida_struct
import ida_funcs

import shannon_generic

# process the scatter load function
def process_scatterload(reset_func_cur):

    scatter_target = next(idautils.CodeRefsFrom(reset_func_cur,  0))

    scatterload = idc.get_operand_value(scatter_target, 0)

    idc.msg("[i[ scatterload(): %x\n" % (scatterload))

    if (scatterload == None):
        idc.msg("[e] scatterload == None\n")
        return

    ida_name.set_name(scatterload, "scatterload", ida_name.SN_NOCHECK)

    return scatterload

# process the scatter table
def process_scattertbl(scatterload):

    scatter_tbl = idc.get_operand_value(scatterload, 1)

    scatter_start = int.from_bytes(
        ida_bytes.get_bytes(scatter_tbl, 4), "little")
    scatter_stop = int.from_bytes(
        ida_bytes.get_bytes(scatter_tbl+4, 4), "little")

    scatter_start = (scatter_start + scatter_tbl) & 0xFFFFFFFF
    scatter_stop = (scatter_stop + scatter_tbl) & 0xFFFFFFFF
    scatter_size = scatter_stop - scatter_start

    struct_id = ida_struct.get_struc_id("scatter")
    struct_size = ida_struct.get_struc_size(struct_id)

    idc.msg("[i] scatter table at %x, size %d, tbl has %d entries\n" %
            (scatter_start, scatter_size, scatter_size/struct_size))

    tbl = read_scattertbl(scatter_start, scatter_size)

    op_list = []

    # first round of processing, define ops (these are the functions which process the scatter data)
    for entry in tbl:

        op = entry[3]
        # realign if we are off by one here due to thumb and stuff
        if (op % 4):
            op += 1

        ida_bytes.del_items(op)
        idc.create_insn(op)
        ida_funcs.add_func(op)

        op_list.append(op)

    # make a "unique" list by converting it to a set and back
    op_list = list(set(op_list))

    # possible scatter ops
    scatter_null = None
    scatter_zero = None
    scatter_copy = None
    scatter_comp = None

    # I am aware that there are some patterns and stuff to identify these which originate in basespec research
    # by KAIST. At this point we already have a very small amout of candidates, decompression algorithms use
    # multiple loops, zeroinit will zero a couple of regs, and cpy will loop to itself. This is easy enough to 
    # tell the scatterload functions apart using metrics instead of a pattern.

    for op in op_list:
        # get boundaries of function
        idc.msg("[i] processing scatter function at %x\n" % op)

        found = False

        # process functions

        metrics = shannon_generic.get_metric(op)

        idc.msg("[d] %x: loops: %d branch: %d length: %d basic blocks: %d xrefs: %d ldr: %d\n" % (
                op, len(metrics[0]), len(metrics[1]), metrics[2], metrics[3], len(metrics[4]), len(metrics[5])))

        scatter_func_offset = op

        opcode = ida_ua.ua_mnem(scatter_func_offset)
        if (opcode == "MOVS"):
            scatter_func_offset = idc.next_head(scatter_func_offset)
            opcode = ida_ua.ua_mnem(scatter_func_offset)
            if (opcode == "MOVS"):
                # we found zero init
                ida_name.set_name(op, "scatterload_zeroinit",
                                  ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                found = True
                scatter_zero = op
                idc.msg("[i] found scatterload_zeroinit() at %x\n", op)
                break

        for branch in metrics[1]:

            operand = idc.get_operand_value(branch, 0)
            if (operand == op):
                # we found a loop to the first inst, this is copy
                ida_name.set_name(op, "scatterload_copy",
                                  ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                scatter_copy = op
                found = True
                idc.msg("[i] found scatterload_copy() at %x\n", op)
                break

        if ((len(metrics[0]) > 3) and (found == False)):

            # decompression requires a significent amount of loops
            ida_name.set_name(op, "scatterload_decompress",
                              ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            scatter_comp = op
            found = True
            idc.msg("[i] found scatterload_decompress() at %x\n", op)
            continue

        # if it's nothing of the above, it is null
        if (found == False):
            ida_name.set_name(op, "scatterload_null",
                              ida_name.SN_NOCHECK | ida_name.SN_FORCE)

# read and pre-process the scatter table
def read_scattertbl(scatter_start, scatter_size):

    struct_id = ida_struct.get_struc_id("scatter")
    struct_size = ida_struct.get_struc_size(struct_id)
    sptr = ida_struct.get_struc(struct_id)

    tbl = []

    scatter_offset = scatter_start

    while (scatter_offset < (scatter_start+scatter_size)):

        entry = []

        ida_bytes.del_items(scatter_offset, 0,  struct_size)
        ida_bytes.create_struct(scatter_offset, struct_size, struct_id)
        scatter_offset += struct_size

        src_ptr = ida_struct.get_member_by_name(sptr, "src")
        entry.append(int.from_bytes(ida_bytes.get_bytes(
            scatter_offset+src_ptr.soff, 4), "little"))

        dst_ptr = ida_struct.get_member_by_name(sptr, "dst")
        entry.append(int.from_bytes(ida_bytes.get_bytes(
            scatter_offset+dst_ptr.soff, 4), "little"))

        size_ptr = ida_struct.get_member_by_name(sptr, "size")
        entry.append(int.from_bytes(ida_bytes.get_bytes(
            scatter_offset+size_ptr.soff, 4), "little"))

        op_ptr = ida_struct.get_member_by_name(sptr, "op")
        entry.append(int.from_bytes(ida_bytes.get_bytes(
            scatter_offset+op_ptr.soff, 4), "little"))

        tbl.append(entry)

    return tbl

# find scatter related code
def find_scatter():

    mode_switch = 0

    reset_vector_offset = idc.get_name_ea_simple("reset_v")

    # get boundaries of function
    reset_func_start = idc.get_func_attr(
        reset_vector_offset, idc.FUNCATTR_START)
    reset_func_end = idc.get_func_attr(reset_vector_offset, idc.FUNCATTR_END)

    if (reset_func_start != idaapi.BADADDR and reset_func_end != idaapi.BADADDR):

        func_cur = reset_func_start

        while (1):
            func_cur = idc.next_head(func_cur)
            opcode = ida_ua.ua_mnem(func_cur)

            # bailout
            if (opcode == None):
                continue

            if ("MSR" in opcode):
                cpsr = idc.get_operand_value(func_cur, 0)
                cpsr_value = idc.get_operand_value(func_cur, 1)

                if (cpsr == -1):
                    continue

                cpsr_str = ida_idp.get_reg_name(cpsr, 0)

                if ("CPSR" in cpsr_str):
                    if (cpsr_value == 0xD3):

                        if (mode_switch == 0):
                            mode_switch += 1
                            continue

                        idc.msg(
                            "[d] second supervisor mode switch found: %x\n" % func_cur)

                        reset_func_cur = func_cur

                        while (1):
                            reset_func_cur = idc.next_head(reset_func_cur)
                            reset_opcode = ida_ua.ua_mnem(reset_func_cur)

                            # bailout
                            if (reset_opcode == None):
                                idc.msg("[e] no reset_opcode\n")
                                return

                            # scatterload is the first branch in main, right after the crt (reset vector)
                            if ("B" == reset_opcode):

                                scatterload = process_scatterload(
                                    reset_func_cur)
                                process_scattertbl(scatterload)

                            # abort if nothing was found
                            if (reset_func_cur >= reset_func_end):
                                return

            if (func_cur >= reset_func_end):
                return


find_scatter()

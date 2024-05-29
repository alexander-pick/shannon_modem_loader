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
import ida_auto

import shannon_generic

# process the scatter load function
def process_scatterload(reset_func_cur):

    scatter_target = next(idautils.CodeRefsFrom(reset_func_cur,  0))

    scatterload = idc.get_operand_value(scatter_target, 0)

    idc.msg("[i] scatterload(): %x\n" % (scatterload))

    if (scatterload == None):
        idc.msg("[e] scatterload == None\n")
        return

    ida_name.set_name(scatterload, "scatterload", ida_name.SN_NOCHECK)

    return scatterload

# recreate function at the given offset, i.e. if something was re-aligned around it
# this has to be done sometimes in RT optimized code to get proper results
def recreate_function(op):
    ida_bytes.del_items(op)
    idc.create_insn(op)
    ida_funcs.add_func(op)
    func_o = ida_funcs.get_func(op)
                    
    if func_o is not None:
        ida_funcs.update_func(func_o)
        ida_funcs.reanalyze_function(func_o)
        ida_auto.auto_wait()

# create the scatter table
def create_scatter_tbl(scatterload):

    recreate_function(scatterload)

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
    
    ida_name.set_name(scatter_start, "scatter_tbl", ida_name.SN_NOCHECK)

    tbl = read_scattertbl(scatter_start, scatter_size)

    op_list = []

    # first round of processing, define ops (these are the functions which process the scatter data)
    for entry in tbl:

        op = entry[3]
        # realign if we are off by one here due to thumb and stuff
        if (op % 4):
            op += 1

        recreate_function(op)

        op_list.append(op)

    # make a "unique" list by converting it to a set and back
    op_list = list(set(op_list))

    return # currently disabled, working on / waiting for a fix for the graph in IDA going mad 

    ops = find_scatter_functions(op_list)
    process_scattertbl(scatter_start, scatter_size, ops)

def find_scatter_functions(op_list):

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

        recreate_function(op)

        metrics = shannon_generic.get_metric(op)

        shannon_generic.print_metrics(op, metrics)

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

                if(scatter_zero != None):
                    idc.msg("[e] scatterload_zeroinit() found at %x, already found at %x before\n" % (op, scatter_zero))
                else:    
                    scatter_zero = op
                    idc.msg("[i] found scatterload_zeroinit() at %x\n" % op)
                break

        for branch in metrics[0]:

            operand = idc.get_operand_value(branch, 0)

            if (operand == op):
                # we found a loop to the first inst, this is copy
                ida_name.set_name(op, "scatterload_copy",
                                  ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                
                found = True
                
                if(scatter_copy != None):
                    idc.msg("[e] scatterload_copy found() at %x, already found at %x before\n" % (op, scatter_copy))
                else:    
                    scatter_copy = op
                    idc.msg("[i] found scatterload_copy() at %x\n" % op)
                break

        if ((len(metrics[0]) > 3) and (found == False)):

            # decompression requires multiple loops
            ida_name.set_name(op, "scatterload_decompress",
                              ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            
            found = True

            if(scatter_comp != None):
                    idc.msg("[e] scatterload_decompress() found at %x, already found at %x before\n" % (op, scatter_comp))
            else:    
                scatter_comp = op
                idc.msg("[i] found scatterload_decompress() at %x\n"  % op)
            continue

        # if it's nothing of the above, it is null
        if (found == False):
            ida_name.set_name(op, "scatterload_null",
                              ida_name.SN_NOCHECK | ida_name.SN_FORCE)
            scatter_null = op
            
    return [scatter_null, scatter_zero , scatter_copy, scatter_comp]

# entry
# 1 - src
# 2 - dst
# 3 - size
# 4 - op

def process_scattertbl(scatter_start, scatter_size, ops):

    tbl = read_scattertbl(scatter_start, scatter_size)

    scatter_id = 0

    for entry in tbl:

        idc.msg("[i] processing scatter - src:%x dst: %x size: %d op: %x\n" % (entry[0],entry[1],entry[2],entry[3]))
       
        index = 0
        for op in ops:
            if(entry[3] == op):
                match index:
                    case 0:
                        idc.msg("[d] scatter_null\n")
                        # ignore this for now
                    case 1:
                        idc.msg("[d] scatter_zero\n")
                        # let's ignore that for now
                    case 2:
                        idc.msg("[d] scatter_copy\n")
                        # copy in idb
                        if(entry[2] > 0):
                            # create a new segment for the scatter and copy bytes over
                            shannon_generic.add_memory_segment(entry[1], entry[2], "SCATTER_"+str(scatter_id), "CODE", False)
                            chunk = ida_bytes.get_bytes(entry[0], entry[2])
                            ida_bytes.put_bytes(entry[1], chunk)
                    case 3:
                        idc.msg("[d] scatter_comp\n")
                        # todo, implement decompression
            index += 1
        scatter_id += 1

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
        scatter_offset += struct_size

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
                                create_scatter_tbl(scatterload)

                            # abort if nothing was found
                            if (reset_func_cur >= reset_func_end):
                                return

            if (func_cur >= reset_func_end):
                return

# find_scatter()

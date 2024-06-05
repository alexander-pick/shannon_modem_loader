#!/bin/python3

# Samsung Shannon Modem Loader - Generic Functions
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

import idc
import idaapi
import ida_segment
import ida_bytes
import ida_ua
import ida_name
import idautils
import ida_idp
import ida_nalt
# import ida_funcs
# import ida_auto

# adds a memory segment to the database
def add_memory_segment(seg_start, seg_size, seg_name, seg_type="DATA", sparse=True):

    # sanity check
    if(seg_size < 0):
        idc.msg("[e] cannot create a segment at %x with negative size %d\n" % (seg_start, seg_size))
        return
    
    if(seg_start == 0xFFFFFFFF):
        idc.msg("[e] cannot create a segment at 0xFFFFFFFF\n")
        return

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

    bytes = ida_bytes.get_bytes(str_addr, 4)

    # bailout - hardly happens, only with some rare oddly formated input files
    if(bytes == None):
        idc.msg("[e] cannot resolve string reference at %x\n" % str_addr)
        return None

    str_offset = int.from_bytes(bytes, "little")
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

# The function can be used in 2 ways - for fingerprinting and finding a specific 
# function in a small group of candidates - or - for getting all branches, ldr,
# xrefs etc. of a function with a single call

# function returns:
# 0 - loops -> list with offsets
# 1 - branch -> list with offsets
# 2 - length -> count
# 3 - bb -> count
# 4 - xrefs -> list with offsets
# 5 - ldrs -> list with offsets

def get_metric(bl_target):

    loops = []
    branch = []
    ldr = []
    xrefs = []
    calls = []

    length = 0
    flow_size = 0
    
    func_start = idc.get_func_attr(bl_target, idc.FUNCATTR_START)
    func_end = idc.get_func_attr(bl_target, idc.FUNCATTR_END)

    #idc.msg("[d] get_metrics(%x) -> %x %x\n" % (bl_target, func_start, func_end))

    func_cur = bl_target

    # check that we don't validate the void
    if (func_end != idaapi.BADADDR and func_cur != idaapi.BADADDR):

        while (func_cur < func_end):

            length += 1
            func_cur = idc.next_head(func_cur)
            #idc.msg("[d] offset %x\n" % func_cur)

            opcode = ida_ua.ua_mnem(func_cur)

            # bailout
            if (opcode == None):
                #idc.msg("[d] no opcode at %x\n" % func_cur)
                continue

            # we reached the end of the world
            if(ida_idp.is_ret_insn(func_cur)):
                # disabled, caused issues with IDA auto analysis
                #if(func_cur != func_end and idc.next_head(func_cur) != func_end):

                    # # # something is off, let's realign, happens in optimzed RT code
                    # func_o = ida_funcs.get_func(func_start)
                    
                    # if func_o is not None:
                    #     idc.msg("[d] differing boundaries for function at %x -> end was %x should be %x\n" % (func_start, func_end, func_cur))
                    #     func_o.end_ea = func_cur
                    #     func_end = func_cur
                    #     ida_funcs.update_func(func_o)
                    #     ida_funcs.reanalyze_function(func_o)
                    #     ida_auto.auto_wait()
                        # ida_funcs.del_func(func_start)
                        # ida_funcs.add_func(func_start, func_cur)
                
                break

            # check if a basic block ends or call, if so, it is a branch (exclude return instructions)
            if ((ida_idp.is_basic_block_end(func_cur,0) or ida_idp.is_call_insn(func_cur)) and not ida_idp.is_ret_insn(func_cur)):

                first_operand = idc.get_operand_value(func_cur, 0)

                if(first_operand != idaapi.BADADDR):

                    if(ida_idp.is_call_insn(func_cur)):
                        #idc.msg("[d] %s call at %x -> %x\n" % (opcode, func_cur, first_operand))
                        calls.append(func_cur)
                    elif (first_operand >= func_start and func_cur > first_operand):
                        # jump backwards inside function, most likely a loop
                        #idc.msg("[d] %s loop at %x -> %x\n" % (opcode, func_cur, first_operand))
                        loops.append(func_cur)
                    else:
                        #idc.msg("[d] %s branch at %x -> %x\n" % (opcode, func_cur, first_operand))
                        branch.append(func_cur)

                else:
                    idc.msg("[e] errorous branch target at %x -> %x\n" % (func_cur, first_operand))


            if ("LDR" in opcode):
                ldr.append(idc.get_operand_value(func_cur, 1))

        # get basic block count of function
        function = idaapi.get_func(func_start)

        if(function != None):
            flow_chart = idaapi.FlowChart(function)
            flow_size = flow_chart.size
        else:
            idc.msg("[e] error getting flowchart for function at %x" % func_start)

        xrefs = list(idautils.XrefsTo(func_start, 0))

    return [loops, branch, length, flow_size, xrefs, ldr, calls]

# print metrics from get_metrics() for dbg reasons
def print_metrics(addr, metrics):
    idc.msg("[d] %x: loops: %d branch: %d length: %d basic blocks: %d xrefs: %d ldr: %d calls: %d\n" % (
        addr, len(metrics[0]), len(metrics[1]), metrics[2], metrics[3], len(metrics[4]), len(metrics[5]), len(metrics[6])))

# rolled a own txt search based on bin search here, I wasn't happy with 
# how ida_search.find_text() works for my usecase - moar performance
def search_text(start_ea, end_ea, text):
    
    patterns = ida_bytes.compiled_binpat_vec_t()
    encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
    
    if text.find('"') < 0:
        text = '"%s"' % text
    
    err = ida_bytes.parse_binpat_str(patterns, start_ea, text, 10, encoding)
    
    if(not err):
        ea = ida_bytes.bin_search(start_ea, end_ea, patterns, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW)
                
        return ea

    return idaapi.BADADDR

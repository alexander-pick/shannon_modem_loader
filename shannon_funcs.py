#!/bin/python3

# Samsung Shannon Modem Loader - Function Related Functions
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024-2025

import idc
import idaapi
import ida_segment
import ida_bytes
import ida_ua
import ida_name
import idautils
import ida_idp
import ida_nalt
import ida_funcs
import ida_auto

import shannon_generic

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

# this fixes badly aligned functions in newer BB versions
# some of them get combined by AA because of the stack protection
# ... takes ages to run, therefore not used atm.
def split_functions():
    stack_err = idc.get_name_ea_simple("stack_err")
    for xref in idautils.XrefsTo(stack_err, 0):
        prev_head = idc.prev_head(xref.frm)
        opcode = ida_ua.ua_mnem(prev_head)

        if (opcode == None):
            continue

        if ("POP" in opcode):

            func_start = idc.get_func_attr(prev_head, idc.FUNCATTR_START)
            func_end = idc.get_func_attr(prev_head, idc.FUNCATTR_END)

            func_o = ida_funcs.get_func(func_start)

            if func_o is not None:
                if (func_o.end_ea != prev_head or func_o.end_ea != xref.frm):
                    # shannon_generic.DEBUG("[d] differing boundaries for function at %x, setting end to %x, was %x\n" % (
                    #     func_start, prev_head, func_end))
                    func_o.end_ea = prev_head
                    ida_funcs.update_func(func_o)
                    ida_funcs.reanalyze_function(func_o)
                    ida_auto.auto_wait()

# adds not yet defined functions which failed in AA due to stack protection
# functionality for very new BB images. IDA gets confused by the non returning
# tail which ends in an error handler. We use the error handler as reference
# to proper define the functions AA cannot define.
# ... takes ages to run, therefore not used atm.
def scan_main():

    # do some cleanup first
    #split_functions()

    stack_err = idc.get_name_ea_simple("stack_err")

    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    addr = seg_t.start_ea

    while (addr < seg_t.end_ea):
        #is offset code?"
        if (idc.is_code(idc.get_full_flags(addr))):

            # this simply prevents that we define a check fail as function start
            opcode = ida_ua.ua_mnem(addr)

            if (opcode == None):
                continue

            if ("BL" in opcode):
                operand = idc.get_operand_value(addr, 0)

                if (operand != None):

                    if (operand == stack_err):
                        addr = idc.next_head(addr)
                        continue

            # offset is part of a function?
            if (idc.get_func_attr(addr, idc.FUNCATTR_START) == idaapi.BADADDR):
                # check if we can find a stack check fail tail
                tail_offset = shannon_generic.func_find_tail(addr, stack_err)

                if (tail_offset != None):

                    # avoid defining the tail as own functions
                    if (addr != tail_offset):
                        ida_funcs.add_func(addr, tail_offset)
                        # shannon_generic.DEBUG("[d] found a function %x-%x\n" % (addr, tail_offset))

        addr = idc.next_head(addr)

# tries to determain function bondaries if an important function is not defined
# happens due to stack protection which confuses AA
def function_find_boundaries(addr):

    stack_err = idc.get_name_ea_simple("stack_err")

    #shannon_generic.DEBUG("[d] stack_err: %x\n" % stack_err)

    if (stack_err == idaapi.BADADDR):
        return False

    while (1):

        #shannon_generic.DEBUG("[d] function_find_boundaries() - cur: %x\n" % addr)

        opcode = ida_ua.ua_mnem(addr)

        # part of a function, undefined or whatever?
        if ((idc.get_func_attr(addr, idc.FUNCATTR_START) != idaapi.BADADDR) or not idc.is_code(idc.get_full_flags(addr)) or opcode == None):

            prev_addr = idc.next_head(addr)

            opcode = ida_ua.ua_mnem(prev_addr)
            if (opcode == None):
                #shannon_generic.DEBUG("[d] no opcode at %x\n" % (prev_addr))
                break

            if ("PUSH" in opcode):

                tail_offset = function_find_tail(prev_addr, stack_err)

                if (tail_offset != None):

                    # avoid defining the tail as own functions
                    if (prev_addr != tail_offset):
                        ida_funcs.add_func(prev_addr, tail_offset)
                        idc.msg("[i] created a function %x-%x\n" % (prev_addr, tail_offset))
                        return True
            else:
                # bailout or we run forever
                #shannon_generic.DEBUG("[d] not a PUSH, bailout at %x\n" % (prev_addr))
                return False

        addr = idc.prev_head(addr)

    return False

# finds the end of the function based on the call to the failed stack
# validation
def function_find_tail(addr, stack_err):

    while (1):

        addr = idc.next_head(addr)
        opcode = ida_ua.ua_mnem(addr)

        # sanity checks / bailout conditions

        # not defined opcode
        if (opcode == None):
            break

        # found no code
        if (not idc.is_code(idc.get_full_flags(addr))):
            break

        # found code belonging to a function
        if (not idc.get_func_attr(addr, idc.FUNCATTR_START) == idaapi.BADADDR):
            break

        if ("BL" in opcode):
            operand = idc.get_operand_value(addr, 0)

            if (operand != None):

                if (operand == stack_err):
                    paddr = idc.prev_head(addr)
                    opcode = ida_ua.ua_mnem(paddr)

                    if (opcode == None):
                        break

                    if ("POP" in opcode):
                        return paddr
                    else:
                        addr = idc.next_head(addr)
                        continue

    return None

# simple mangler
# if not mangled, all the :: and stuff get's lost if setting the name
def mangle_name(name):
    
    name_len = len(name)
    
    parts = name.split("::")
    
    mangled_name = "_Z"

    if(len(parts) > 1): 
        
        first_part = True
        
        for part in parts:
            
            if first_part:
                mangled_name += "N"
                first_part = False
                
            mangled_name += str(len(part))+str(part)

    else:
        
        mangled_name += str(name_len) + name
        
    mangled_name += "E"
        
    return mangled_name
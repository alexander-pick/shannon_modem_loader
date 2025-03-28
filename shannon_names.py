#!/bin/python3

# Samsung Shannon Modem Loader - Name Reconstruction
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024-2025

import idc
import ida_bytes
import ida_nalt
import idautils
import idaapi
import ida_segment
import ida_search
import ida_ua
import ida_funcs

import re
import os

import shannon_generic
import shannon_funcs

def restore_cpp_names():

    idc.msg("[i] trying to reconstruct cpp names from strings\n")
    sc = idautils.Strings()

    for i in sc:
        # step 1 - find a function name
        regex = "([a-z]*::[A-Za-z_]*::[A-Za-z_]*)"

        if (re.match(regex, str(i))):
            shannon_generic.create_name(i.ea, str(i))

# restores the function names of SS related functions from a macro created function structure

def restore_ss_names():

    idc.msg("[i] trying to reconstruct ss names from function macros\n")

    # step 1 - find a function name

    # search only in main to avoid unnecessary long runtimes
    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    ss_offset = shannon_generic.search_text(
        seg_t.start_ea, seg_t.end_ea, "ss_DecodeGmmFacilityMsg")

    if (ss_offset != idaapi.BADADDR):
        
        # step 2 - find xrefs to this name, essentially should be just one xref
        for xref in idautils.XrefsTo(ss_offset, 0):

            # sanity check - validate that xref target is a function, or next
            if (idc.get_func_attr(xref.frm, idc.FUNCATTR_START) == idaapi.BADADDR):
                continue
            
            # step 3 - iterate over the next instructions until we find a function call

            xref_str = None
            tries = 0
            prev_offset = xref.frm

            while (tries < 5):
                
                # forward search, max 5 instructions
                xref_str_tmp = idc.next_head(prev_offset)
                opcode = ida_ua.ua_mnem(xref_str_tmp)
                
                if (opcode == None):
                    tries += 1
                    continue
                
                if ("BL" in opcode):
                    # shannon_generic.DEBUG("[d] found BL at %x\n" % xref_str_tmp)
                    # docs said this is a list, but seems to be a generator?
                    xref_str = next(
                        idautils.CodeRefsFrom(xref_str_tmp, 0))
                    break
                else:
                    prev_offset = xref_str_tmp
                    tries += 1

            if (xref_str == None):
                continue  # abort if not foudn or emptyt list

            idc.msg("[i] found verbose ss_ name function: %x\n" % xref_str)
            
            check_failed = 0

            # step 4 - iterate over the all calls to this function
            for xref_func in idautils.XrefsTo(xref_str, 0):

                tries = 0
                prev_offset = xref_func.frm

                while (tries < 5):
                    
                    cur_offset = idc.prev_head(prev_offset)
                    opcode = ida_ua.ua_mnem(cur_offset)
                    
                    if (opcode == None):
                        tries += 1
                        continue
                    
                    # Thanks John Doe
                    if ("DR" in opcode and idc.get_operand_value(cur_offset, 0) == 0x0):
                        # shannon_generic.DEBUG("[d] found LDR at %x\n" % cur_offset)
                        break
                    else:
                        prev_offset = cur_offset
                        tries += 1

                # get LDR param which is the function name
                str_addr = idc.get_operand_value(cur_offset, 1)

                # read string
                func_name = idc.get_strlit_contents(str_addr)

                # sanity checks
                if (func_name == None):
                    # shannon_generic.DEBUG("[d] %x: failed sanity check (None)\n" % str_addr)
                    check_failed = 1
                    
                # this in elif to avoid err with undefined bla
                elif (len(func_name.decode()) < 8):
                    # shannon_generic.DEBUG("[d] %x: failed sanity check (length)\n" % str_addr)
                    check_failed = 1

                if check_failed:
                    # try to resolve ref
                    func_name = shannon_generic.resolve_ref(str_addr)

                    if (func_name == None):
                        # idc.msg(
                        #     "[e] %x: function name not defined\n" % str_addr)
                        continue

                func_name_str = func_name.decode()

                # shannon_generic.DEBUG("[d] %x: found function name %s\n" % (str_addr, func_name_str))

                if ("ss_" not in func_name_str):
                    idc.msg("[e] %x: failed to find function name for %x, found '%s' instead\n" % (
                        str_addr, xref_func.frm, func_name))
                    continue

                # create a string at string offfset
                ida_bytes.create_strlit(str_addr, 0, ida_nalt.STRTYPE_C)

                func_start = idc.get_func_attr(
                    xref_func.frm, idc.FUNCATTR_START)

                if (func_start != idaapi.BADADDR):

                    if (len(func_name_str) > 8):    

                        func_name = shannon_funcs.function_find_name(func_name_str)       

                        idaapi.set_name(func_start, func_name)
                    else:
                        idc.msg("[e] %x: function name too short: %s" %
                                (func_start, func_name_str))
                else:
                    # shannon_generic.DEBUG("[d] not a function, searching for start\n")
                    cur_offset = xref_func.frm
                    prev_offset = 0
                    # find func boundaries
                    
                    tries = 150
                    
                    while tries:
                        
                        # possible bailout
                        tries -= 1
                        
                        flags = idc.get_func_flags(cur_offset)
                        opcode = ida_ua.ua_mnem(cur_offset)

                        if ((flags == -1) and (opcode != None)):
                            
                            prev_offset = cur_offset
                            cur_offset = idc.prev_head(cur_offset)
                            
                        else:

                            ida_funcs.add_func(
                                prev_offset, idc.prev_head(str_addr))
                            idaapi.set_name(
                                prev_offset, shannon_funcs.function_find_name(func_name_str))
                            break

#for debugging purpose export SHANNON_WORKFLOW="NO"
if (os.environ.get('SHANNON_WORKFLOW') == "NO"):
    idc.msg("[i] running names in standalone mode")


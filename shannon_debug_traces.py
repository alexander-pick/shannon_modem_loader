#!/bin/python3

# Samsung Shannon Modem Loader - Debug Traces
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024-2025

import idc
import ida_bytes
import ida_nalt
import idautils
import idaapi

import os
import shannon_structs

# this creates cmts from previously created dbt structures to anote
# functions with their source paths and string refs
def make_dbt_refs():

    idc.msg("[i] creating dbt references\n")

    struct_id = idc.get_struc_id("dbg_trace")
    all_structs = idautils.XrefsTo(struct_id, 0)
    
    tif = shannon_structs.get_struct(struct_id)
    
    # moved out of the for loop for performance reasons
    str_ptr = shannon_structs.get_offset_by_name(tif, "msg_ptr")
    file_ptr = shannon_structs.get_offset_by_name(tif, "file")

    for i in all_structs:
       
        str_offset = int.from_bytes(
            ida_bytes.get_bytes((i.frm+str_ptr), 4), "little")
        
        # creating is mostly not needed but we do it to make sure it is defined
        ida_bytes.create_strlit(str_offset, 0, ida_nalt.STRTYPE_C)
        msg_str = idc.get_strlit_contents(str_offset)
        
        # shannon_generic.DEBUG("[d] make_dbt_refs() %x: %s\n" % (str_offset, msg_str))
        file_offset = int.from_bytes(
            ida_bytes.get_bytes((i.frm+file_ptr), 4), "little")
        
        ida_bytes.create_strlit(file_offset, 0, ida_nalt.STRTYPE_C)
        file_str = idc.get_strlit_contents(file_offset)
        
        # shannon_generic.DEBUG("[d] make_dbt_refs() %x: %s\n" % (file_offset, file_str))

        # find xref to struct
        for xref_dbt in idautils.XrefsTo(i.frm,  0):
            if (msg_str != None):
                idaapi.set_cmt(xref_dbt.frm, msg_str.decode(), 1)

                func_start = idc.get_func_attr(
                    xref_dbt.frm, idc.FUNCATTR_START)

                if (func_start != idaapi.BADADDR):
                    if (file_str != None):
                        idaapi.set_func_cmt(
                            func_start, file_str.decode(), 1)

#for debugging purpose export SHANNON_WORKFLOW="NO"
if (os.environ.get('SHANNON_WORKFLOW') == "NO"):
    idc.msg("[i] running debug traces in standalone mode")
    make_dbt_refs()
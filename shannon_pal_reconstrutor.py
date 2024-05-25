#!/bin/python3

# Samsung Shannon Modem Postprocessor
# This script is autoamtically executed by the loader
# Alexander Pick 2024

import idc
import idaapi
import idautils
import ida_bytes
import ida_name
import ida_ua
import ida_struct
import ida_nalt

# This code identifies a couple of functions of the platform abstraction layer and uses
# these to find the task table. This could be done in a much simpler fashion by searching
# for PALTskTm and work from there, but using the heuristic below a couple of func refs
# will be reconstructed and named which are quite important for future analysis

def find_basic_pal_functions():

    sc = idautils.Strings()

    pal_MsgSendTo_addr = idaapi.BADADDR

    for i in sc:

        # step 1 - find pal_MsgSendTo()
        if("PAL_MSG_MAX_ENTITY_COUNT" in str(i)):

            # realign if we are off by one here (happens)
            if(i.ea % 4):
                i.ea += 1

            # most images have 2 xrefs to this string, ones is MsgSendTo
            for xref in idautils.XrefsTo(i.ea, 0):

                func_start = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)

                num_xrefs = len(list(idautils.XrefsTo(func_start, 0)))

                #pal_MsgSendTo has a lot of xrefs to itself, other candidate funcs don't have that
                if(num_xrefs > 15):

                    pal_MsgSendTo_addr = func_start

                    # sanity check - validate that xref target is a function, or next
                    if(pal_MsgSendTo_addr ==  idaapi.BADADDR):
                        continue

                    print("[i] pal_MsgSendTo(): %x" % pal_MsgSendTo_addr)
                    ida_name.set_name(pal_MsgSendTo_addr, "pal_MsgSendTo", ida_name.SN_NOCHECK | ida_name.SN_FORCE)

    find_pal_msg_init(pal_MsgSendTo_addr)

def find_pal_msg_init(pal_MsgSendTo_addr):
    #step2 - find pal_MsgInit()
    if(pal_MsgSendTo_addr != idaapi.BADADDR):
        
        func_cnt = 1
        tbl_cnt = 1
        pal_MsgInit_addr = pal_MsgSendTo_addr
        found_msg_init = False

        while(func_cnt < 4):

            # get a candidate get_prev_func returns a func_t :S
            pal_MsgInit_addr_t = idaapi.get_prev_func(pal_MsgInit_addr)
            pal_MsgInit_addr = pal_MsgInit_addr_t.start_ea

            que_init_addr = idc.next_head(pal_MsgInit_addr)

            # check if second opcode of function is a BL
            opcode = ida_ua.ua_mnem(que_init_addr)

            # step3, find pal_QueInit to make sure we have the right parent function
            # A call to pal_QueInit is located directly after the reg save of pal_MsgInit
            if("BL" in opcode):
                # yes, so we found pal_QueInit, get the target offset
                target_ref = idc.get_operand_value(que_init_addr, 0)

                print("[i] pal_QueInit(): %x" % target_ref)
                ida_name.set_name(target_ref, "pal_QueInit", ida_name.SN_NOCHECK)

                # low xp sidequest - find MsgDescriptorTbl (because we can)
                while(tbl_cnt < 5):

                    task_desc_offset = pal_MsgInit_addr+4+(4*tbl_cnt)

                    opcode = ida_ua.ua_mnem(task_desc_offset)

                    if(opcode == "LDR"):
                        target_ref = idc.get_operand_value(task_desc_offset, 1)
                        target = int.from_bytes(ida_bytes.get_bytes(target_ref, 4), "little")

                        print("[i] pal_MsgDescriptorTbl(): %x" % target)
                        ida_name.set_name(target, "pal_MsgDescriptorTbl", ida_name.SN_NOCHECK)

                    tbl_cnt += 1

                found_msg_init = True
                print("[i] pal_MsgInit(): %x" % pal_MsgInit_addr)
                ida_name.set_name(pal_MsgInit_addr, "pal_MsgInit", ida_name.SN_NOCHECK)

                break

            func_cnt += 1

        # step 4 - find the parent of pal_MsgInit which is pal_Init
        # pal_init is a nice starting point for everything since it is the startup
        # of the interesting pal functionality
        find_pal_init(found_msg_init, pal_MsgInit_addr)

def find_pal_init(found_msg_init, pal_MsgInit_addr):
    if(found_msg_init):
        # step 3, find PAL init (there should be just one xref here)
        for xref in idautils.XrefsTo(pal_MsgInit_addr, 0):

            pal_init_addr = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)

            print("[i] pal_Init(): %x" % pal_init_addr)
            ida_name.set_name(pal_init_addr, "pal_Init", ida_name.SN_NOCHECK)

            func_start = idc.get_func_attr(pal_init_addr, idc.FUNCATTR_START)
            func_end = idc.get_func_attr(pal_init_addr, idc.FUNCATTR_END)

            if(func_start != idaapi.BADADDR and func_end != idaapi.BADADDR):

                func_cur = func_start

                while(1):
                    func_cur = idc.next_head(func_cur)
                    opcode = ida_ua.ua_mnem(func_cur)

                    #bailout 
                    if(opcode == None):
                        continue

                    if("BL" in opcode):
                        bl_target = idc.get_operand_value(func_cur, 0)
                        #print("[d] possible init function: %x" % bl_target)
                        validate_if_task_scheduler(bl_target)

                    if(func_cur >= func_end):
                        break

# this function checks if the given function might be the task scheduler
def validate_if_task_scheduler(bl_target):
    
    init_func_start = idc.get_func_attr(bl_target, idc.FUNCATTR_START)
    init_func_end = idc.get_func_attr(bl_target, idc.FUNCATTR_END)

    if(init_func_start != idaapi.BADADDR and init_func_end != idaapi.BADADDR):

        init_func_cur = init_func_start

        while(1):
            init_func_cur = idc.next_head(init_func_cur)
            init_opcode = ida_ua.ua_mnem(init_func_cur)

            #bailout 
            if(init_opcode == None):
                break

            if("ADR" in init_opcode):
                init_adr_str = idc.get_operand_value(init_func_cur, 1)
                task_str = idc.get_strlit_contents(init_adr_str)
                if("PALTskTm" in str(task_str)):
                    print("[i] pal_TaskMngrInit(): %x" % init_func_start)
                    ida_name.set_name(init_func_start, "pal_TaskMngrInit", ida_name.SN_NOCHECK)
                    find_task_desc_tbl(init_func_start, init_func_end)                        
                    break

            # abort if nothing was found
            if(init_func_cur >= init_func_end):
                break

# step 6 - find the second LDR in the function. It is the TaskDescTbl
def find_task_desc_tbl(task_func_start, task_func_end):

    task_func_cur = task_func_start

    ldr_cnt = 0

    while(1):
        task_func_cur = idc.next_head(task_func_cur)
        task_opcode = ida_ua.ua_mnem(task_func_cur)

        if("LDR" in task_opcode):

            if(ldr_cnt == 1):
                target_ref = idc.get_operand_value(task_func_cur, 1)
                tbl_offset = int.from_bytes(ida_bytes.get_bytes(target_ref, 4), "little")
                ida_name.set_name(tbl_offset, "pal_TaskDescTbl", ida_name.SN_NOCHECK)

                print("[i] pal_TaskDescTbl(): %x" % tbl_offset)

                identify_task_init(tbl_offset)

            ldr_cnt += 1

        # bailout
        if(task_func_cur >= task_func_end):
            break

def identify_task_init(tbl_offset):

    add_task_struct()

    MAX_TASKS = 256
    tasks = 0

    struct_id = ida_struct.get_struc_id("task_struct")
    struct_size = ida_struct.get_struc_size(struct_id)
    sptr = ida_struct.get_struc(struct_id)

    while(1):

        ida_bytes.del_items(tbl_offset, 0,  struct_size)
        ida_bytes.create_struct(tbl_offset, struct_size, struct_id) 

        str_ptr = ida_struct.get_member_by_name(sptr, "task_name")
        str_offset = int.from_bytes(ida_bytes.get_bytes(tbl_offset+str_ptr.soff, 4), "little")
        ida_bytes.create_strlit(str_offset, 0, ida_nalt.STRTYPE_C)
        task_name_str = idc.get_strlit_contents(str_offset)

        entry_ptr = ida_struct.get_member_by_name(sptr, "task_entry")
        entry_offset = int.from_bytes(ida_bytes.get_bytes(tbl_offset+entry_ptr.soff, 4), "little")

        if(entry_offset == 0x0):
            break

        task_entry_func_start = idc.get_func_attr(entry_offset, idc.FUNCATTR_START)

        if(task_entry_func_start !=  idaapi.BADADDR):

            print("[i] found task init for %s at %x" % (str(task_name_str.decode()), task_entry_func_start))
            ida_name.set_name(task_entry_func_start, "pal_TaskInit_"+str(task_name_str.decode()), ida_name.SN_NOCHECK | ida_name.SN_FORCE)

        tbl_offset += struct_size

        tasks += 1
        if(tasks > MAX_TASKS):
            break

def add_task_struct():
    #Task Structure
    struct_id = idc.add_struc(0, "task_struct", 0)
    idc.add_struc_member(struct_id, "gap_0", -1, idaapi.FF_BYTE, -1, 8) 
    idc.add_struc_member(struct_id, "state", -1, idaapi.FF_BYTE, -1, 1) 
    idc.add_struc_member(struct_id, "flag", -1, idaapi.FF_BYTE, -1, 1) 
    idc.add_struc_member(struct_id, "gap_1", -1, idaapi.FF_BYTE, -1, 1) 
    idc.add_struc_member(struct_id, "gap_2", -1, idaapi.FF_BYTE, -1, 1) 
    idc.add_struc_member(struct_id, "task_num", -1, idaapi.FF_DWORD, -1, 4) 
    idc.add_struc_member(struct_id, "stack", -1, idaapi.FF_DWORD, -1, 4)
    idc.add_struc_member(struct_id, "gap_3", -1, idaapi.FF_BYTE, -1, 0x10)
    idc.add_struc_member(struct_id, "task_name", -1, idaapi.FF_DATA|idaapi.FF_DWORD|idaapi.FF_0OFF, -1, 4)
    idc.add_struc_member(struct_id, "priority", -1, idaapi.FF_BYTE, -1, 1)
    idc.add_struc_member(struct_id, "gap_4", -1, idaapi.FF_BYTE, -1, 3)
    idc.add_struc_member(struct_id, "stack_size", -1, idaapi.FF_DWORD, -1, 4)
    idc.add_struc_member(struct_id, "task_entry", -1, idaapi.FF_DATA|idaapi.FF_DWORD|idaapi.FF_0OFF, -1, 4)
    idc.add_struc_member(struct_id, "task_init", -1, idaapi.FF_DWORD, -1, 4)
    idc.add_struc_member(struct_id, "gap_5", -1, idaapi.FF_BYTE, -1, 4)
    idc.add_struc_member(struct_id, "gap_6", -1, idaapi.FF_BYTE, -1, 0x24)
    idc.add_struc_member(struct_id, "gap_7", -1, idaapi.FF_BYTE, -1, 0x28)
    idc.add_struc_member(struct_id, "gap_8", -1, idaapi.FF_BYTE, -1, 0x78) 
    idc.add_struc_member(struct_id, "gap_9", -1, idaapi.FF_BYTE, -1, 4)
    idc.add_struc_member(struct_id, "gap_10", -1, idaapi.FF_BYTE, -1, 1)
    idc.add_struc_member(struct_id, "gap_11", -1, idaapi.FF_BYTE, -1, 1)
    idc.add_struc_member(struct_id, "gap_12", -1, idaapi.FF_BYTE, -1, 1)
    idc.add_struc_member(struct_id, "gap_13", -1, idaapi.FF_BYTE, -1, 1)
    idc.add_struc_member(struct_id, "gap_14", -1, idaapi.FF_BYTE, -1, 16)  


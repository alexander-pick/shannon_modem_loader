#!/bin/python3

# Samsung Shannon Modem Loader - PAL Reconstructor
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
import ida_search
import ida_segment

import shannon_generic

import os

# This code identifies a couple of functions of the platform abstraction layer and uses
# these to find the task table. This could be done in a much simpler fashion by searching
# for PALTskTm and work from there, but using the heuristic below a couple of func refs
# will be reconstructed and named which are quite important for future analysis
def find_basic_pal_functions():

    idc.msg("[i] trying to identify some important pal functions ands tasks\n")

    # search only in main to avoid unnecessary long runtimes
    seg_t = ida_segment.get_segm_by_name("MAIN_file")
    seg_start = seg_t.start_ea
    seg_end = seg_t.end_ea - seg_t.start_ea

    pal_MsgSendTo_addr = shannon_generic.search_text(seg_start, seg_end, "PAL_MSG_MAX_ENTITY_COUNT")

    # step 1 - find pal_MsgSendTo()
    if (pal_MsgSendTo_addr != idaapi.BADADDR):

        # realign if we are off by one here due to thumb and stuff
        if (pal_MsgSendTo_addr % 4):
            pal_MsgSendTo_addr += 1

        # most images have 2 xrefs to this string, ones is MsgSendTo
        for xref in idautils.XrefsTo(pal_MsgSendTo_addr, 0):

            func_start = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)

            num_xrefs = len(list(idautils.XrefsTo(func_start, 0)))

            # pal_MsgSendTo has a lot of xrefs to itself, other candidate funcs don't have that
            if (num_xrefs > 15):

                pal_MsgSendTo_addr = func_start

                # sanity check - validate that xref target is a function, or next
                if (pal_MsgSendTo_addr == idaapi.BADADDR):
                    continue

                idc.msg("[i] pal_MsgSendTo(): %x\n" % pal_MsgSendTo_addr)
                ida_name.set_name(pal_MsgSendTo_addr, "pal_MsgSendTo",
                                  ida_name.SN_NOCHECK | ida_name.SN_FORCE)

        find_pal_msg_init(pal_MsgSendTo_addr)

# try to find pal_MsgInit() and a few others along
def find_pal_msg_init(pal_MsgSendTo_addr):
    # step2 - find pal_MsgInit()
    if (pal_MsgSendTo_addr != idaapi.BADADDR):

        func_cnt = 1
        tbl_cnt = 1
        pal_MsgInit_addr = pal_MsgSendTo_addr
        found_msg_init = False

        while (func_cnt < 4):

            # get a candidate get_prev_func returns a func_t :S
            pal_MsgInit_addr_t = idaapi.get_prev_func(pal_MsgInit_addr)
            pal_MsgInit_addr = pal_MsgInit_addr_t.start_ea

            que_init_addr = idc.next_head(pal_MsgInit_addr)

            # check if second opcode of function is a BL
            opcode = ida_ua.ua_mnem(que_init_addr)

            # step3, find pal_QueInit to make sure we have the right parent function
            # A call to pal_QueInit is located directly after the reg save of pal_MsgInit
            if ("BL" in opcode):
                # yes, so we found pal_QueInit, get the target offset
                target_ref = idc.get_operand_value(que_init_addr, 0)

                idc.msg("[i] pal_QueInit(): %x\n" % target_ref)
                ida_name.set_name(target_ref, "pal_QueInit",
                                  ida_name.SN_NOCHECK)

                # low xp sidequest - find MsgDescriptorTbl (because we can)
                while (tbl_cnt < 5):

                    task_desc_offset = pal_MsgInit_addr+4+(4*tbl_cnt)

                    opcode = ida_ua.ua_mnem(task_desc_offset)

                    if (opcode == "LDR"):
                        target_ref = idc.get_operand_value(task_desc_offset, 1)
                        target = int.from_bytes(
                            ida_bytes.get_bytes(target_ref, 4), "little")

                        idc.msg("[i] pal_MsgDescriptorTbl(): %x\n" % target)
                        ida_name.set_name(
                            target, "pal_MsgDescriptorTbl", ida_name.SN_NOCHECK)

                    tbl_cnt += 1

                found_msg_init = True
                idc.msg("[i] pal_MsgInit(): %x\n" % pal_MsgInit_addr)
                ida_name.set_name(pal_MsgInit_addr,
                                  "pal_MsgInit", ida_name.SN_NOCHECK)

                break

            func_cnt += 1

        # step 4 - find the parent of pal_MsgInit which is pal_Init
        # pal_init is a nice starting point for everything since it is the startup
        # of the interesting pal functionality
        find_pal_init(found_msg_init, pal_MsgInit_addr)

# try to find pal_Init()
def find_pal_init(found_msg_init, pal_MsgInit_addr):
    if (found_msg_init):
        # step 3, find PAL init (there should be just one xref here)
        for xref in idautils.XrefsTo(pal_MsgInit_addr, 0):

            pal_init_addr = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)

            idc.msg("[i] pal_Init(): %x\n" % pal_init_addr)
            ida_name.set_name(pal_init_addr, "pal_Init", ida_name.SN_NOCHECK)

            metrics = shannon_generic.get_metric(pal_init_addr)
            #shannon_generic.print_metrics(pal_init_addr, metrics)

            for branch in metrics[6]:
                first_operand = idc.get_operand_value(branch, 0)
                #idc.msg("[d] possible init function: %x\n" % branch)
                validate_if_task_scheduler(first_operand)
                #idc.msg("[d] possible dm_trace function: %x\n" % branch)
                validate_if_dm_trace_log(first_operand)

def validate_if_dm_trace_log(bl_target):

    metrics = shannon_generic.get_metric(bl_target)
    #shannon_generic.print_metrics(bl_target, metrics)

    # this function has an insane amount of xrefs, very unique
    if(len(metrics[4]) > 150000):
        idc.msg("[i] dm_TraceMsg(): %x\n" % bl_target)
        ida_name.set_name(bl_target, "dm_TraceMsg", ida_name.SN_NOCHECK)   


# this function checks if the given function might be the task scheduler
def validate_if_task_scheduler(bl_target):

    init_func_start = idc.get_func_attr(bl_target, idc.FUNCATTR_START)
    init_func_end = idc.get_func_attr(bl_target, idc.FUNCATTR_END)

    if (init_func_start != idaapi.BADADDR and init_func_end != idaapi.BADADDR):

        init_func_cur = init_func_start

        while (1):
            init_func_cur = idc.next_head(init_func_cur)
            init_opcode = ida_ua.ua_mnem(init_func_cur)

            # bailout
            if (init_opcode == None):
                break

            if ("ADR" in init_opcode):
                init_adr_str = idc.get_operand_value(init_func_cur, 1)
                task_str = idc.get_strlit_contents(init_adr_str)
                if ("PALTskTm" in str(task_str)):
                    idc.msg("[i] pal_TaskMngrInit(): %x\n" % init_func_start)
                    ida_name.set_name(
                        init_func_start, "pal_TaskMngrInit", ida_name.SN_NOCHECK)
                    find_task_desc_tbl(init_func_start, init_func_end)
                    break

            # abort if nothing was found
            if (init_func_cur >= init_func_end):
                break

# step 6 - find the second LDR in the function. It is the TaskDescTbl
def find_task_desc_tbl(task_func_start, task_func_end):

    task_func_cur = task_func_start

    ldr_cnt = 0

    while (1):
        task_func_cur = idc.next_head(task_func_cur)
        task_opcode = ida_ua.ua_mnem(task_func_cur)

        if ("LDR" in task_opcode):

            if (ldr_cnt == 1):
                target_ref = idc.get_operand_value(task_func_cur, 1)
                tbl_offset = int.from_bytes(
                    ida_bytes.get_bytes(target_ref, 4), "little")
                ida_name.set_name(
                    tbl_offset, "pal_TaskDescTbl", ida_name.SN_NOCHECK)

                idc.msg("[i] pal_TaskDescTbl(): %x\n" % tbl_offset)

                identify_task_init(tbl_offset)

            ldr_cnt += 1

        # bailout
        if (task_func_cur >= task_func_end):
            break


def identify_task_init(tbl_offset):

    MAX_TASKS = 256
    tasks = 0

    struct_id = ida_struct.get_struc_id("task_struct")
    struct_size = ida_struct.get_struc_size(struct_id)
    sptr = ida_struct.get_struc(struct_id)

    while (tasks < MAX_TASKS):

        ida_bytes.del_items(tbl_offset, 0,  struct_size)
        ida_bytes.create_struct(tbl_offset, struct_size, struct_id)

        str_ptr = ida_struct.get_member_by_name(sptr, "task_name")
        str_offset = int.from_bytes(ida_bytes.get_bytes(
            tbl_offset+str_ptr.soff, 4), "little")
        ida_bytes.create_strlit(str_offset, 0, ida_nalt.STRTYPE_C)
        task_name_str = idc.get_strlit_contents(str_offset)

        entry_ptr = ida_struct.get_member_by_name(sptr, "task_entry")
        entry_offset = int.from_bytes(ida_bytes.get_bytes(
            tbl_offset+entry_ptr.soff, 4), "little")

        # break early if we met an undefined entry
        if (entry_offset == 0x0):
            break

        task_entry_func_start = idc.get_func_attr(
            entry_offset, idc.FUNCATTR_START)

        if (task_entry_func_start != idaapi.BADADDR):

            idc.msg("[i] found task init for %s at %x\n" %
                    (str(task_name_str.decode()), task_entry_func_start))
            ida_name.set_name(task_entry_func_start, "pal_TaskInit_"+str(
                task_name_str.decode()), ida_name.SN_NOCHECK | ida_name.SN_FORCE)

        tbl_offset += struct_size

        tasks += 1

#for debugging purpose export SHANNON_WORKFLOW="NO"
if os.environ.get('SHANNON_WORKFLOW') == "NO":
    idc.msg("[i] running pal reconstruct in standalone mode\n")
    find_basic_pal_functions()
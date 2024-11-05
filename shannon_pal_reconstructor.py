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
import ida_nalt
import ida_segment

import shannon_generic
import shannon_funcs
import shannon_structs

import os

# find ref to PALTskTm
def get_PALTskTm_ref():

    seg_t = ida_segment.get_segm_by_name("MAIN_file")
    pal_task_man = shannon_generic.search_text(seg_t.start_ea, seg_t.end_ea, "PALTskTm")
    pal_task_man = shannon_generic.get_first_ref(pal_task_man)

    return pal_task_man

# pad struct
def pad_task_struct(padding):
    struct_id = idc.get_struc_id("task_struct")
    sptr = shannon_structs.get_struct(struct_id)

    str_ptr = shannon_structs.get_offset_by_name(sptr, "padding")
    idc.del_struc_member(struct_id, str_ptr)

    shannon_structs.add_struc_member(
        struct_id, "padding", -1, idaapi.FF_BYTE, -1, padding)

# struct are different in size, since we work with a more or less static start we need to find
# the start offset
# TODO: ssentially it would be correct to extend the struct by X on top but we can simply move the
# start to avoid more fiddelign for now. This will be fixed later
def find_struct_start(tbl_offset, margin):

    # create struct, check string etc.

    tbl_offset += margin

    struct_id = idc.get_struc_id("task_struct")
    sptr = shannon_structs.get_struct(struct_id)

    struct_size = idc.get_struc_size(struct_id)
    str_ptr = shannon_structs.get_offset_by_name(sptr, "task_name")

    ida_bytes.del_items(tbl_offset, 0, struct_size)
    ida_bytes.create_struct(tbl_offset, struct_size, struct_id)

    str_offset = int.from_bytes(ida_bytes.get_bytes((tbl_offset + str_ptr), 4), "little")

    ida_bytes.create_strlit(str_offset, 0, ida_nalt.STRTYPE_C)

    task_name_str = idc.get_strlit_contents(str_offset)

    #clean up
    ida_bytes.del_items(tbl_offset, 0, struct_size)

    if (margin > 0xFF):
        return None

    if (not task_name_str or len(task_name_str) < 5):
        margin += 1
        shannon_generic.DEBUG("[d] testing margin of %x (str: %s len: %d) \n" %
                              (margin, str(task_name_str.decode()), len(task_name_str)))
        tbl_offset = find_struct_start(tbl_offset, margin)
        return tbl_offset

    idc.msg("[i] found real table start at %x , first tasks is %s\n" % (tbl_offset, str(task_name_str.decode())))

    return tbl_offset

# This code identifies a couple of functions of the platform abstraction layer and uses
# these to find the task table. This could be done in a much simpler fashion by searching
# for PALTskTm and work from there, but using the heuristic below a couple of func refs
# will be reconstructed and named which are quite important for future analysis
def find_pal_msg_funcs():

    idc.msg("[i] trying to identify PAL message related functions\n")

    # search only in main to avoid unnecessary long runtimes
    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    pal_MsgSendTo_addr = shannon_generic.search_text(
        seg_t.start_ea, seg_t.end_ea, "PAL_MSG_MAX_ENTITY_COUNT")

    if (pal_MsgSendTo_addr != idaapi.BADADDR):
        # stupid hack to get beginning of the string since we found a substring
        # the PAL_MSG_MAX_ENTITY_COUNT string varies between BB versions so the
        # search is for the most remarkable part only
        pal_MsgSendTo_addr = idc.prev_head(idc.next_head(pal_MsgSendTo_addr))

    # fallback for 5g versions which have the string slightly
    # crippled between hi/lo reg, furthermore the PAL_MSG_MAX_ENTITY_COUNT
    # string is in another function
    if (pal_MsgSendTo_addr == idaapi.BADADDR):
        pal_MsgSendTo_addr = shannon_generic.search_text(
            seg_t.start_ea, seg_t.end_ea, "QUEUE_NAME")

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

        while (func_cnt < 12):

            # get a candidate get_prev_func returns a func_t :S
            pal_MsgInit_addr_t = idaapi.get_prev_func(pal_MsgInit_addr)
            pal_MsgInit_addr = pal_MsgInit_addr_t.start_ea

            que_init_addr = idc.next_head(pal_MsgInit_addr)

            # check if second opcode of function is a BL
            opcode = ida_ua.ua_mnem(que_init_addr)

            if (opcode == None):
                idc.msg("[e] found no opcode at %x\n" % pal_MsgInit_addr)
                continue

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

                    task_desc_offset = pal_MsgInit_addr + 4 + (4 * tbl_cnt)

                    opcode = ida_ua.ua_mnem(task_desc_offset)

                    if (opcode == "LDR"):
                        target_ref = idc.get_operand_value(task_desc_offset, 1)
                        target = int.from_bytes(
                            ida_bytes.get_bytes(target_ref, 4), "little")

                        idc.msg("[i] pal_MsgDescriptorTbl(): %x\n" % target)
                        ida_name.set_name(
                            target, "pal_MsgDescriptorTbl", ida_name.SN_NOCHECK)

                    tbl_cnt += 1

                idc.msg("[i] pal_MsgInit(): %x\n" % pal_MsgInit_addr)
                ida_name.set_name(pal_MsgInit_addr,
                                  "pal_MsgInit", ida_name.SN_NOCHECK)

                break

            func_cnt += 1

# try to find Task SCheduler, Task Inits and pal_Init()
def find_pal_init():

    idc.msg("[i] trying to identify PAL init and tasks\n")

    pal_task_man = get_PALTskTm_ref()

    if (pal_task_man != idaapi.BADADDR):

        func_start = idc.get_func_attr(pal_task_man, idc.FUNCATTR_START)
        func_end = idc.get_func_attr(pal_task_man, idc.FUNCATTR_END)

        if (func_start != idaapi.BADADDR and func_end != idaapi.BADADDR):

            idc.msg("[i] pal_TaskMngrInit(): %x\n" % func_start)
            ida_name.set_name(func_start, "pal_TaskMngrInit", ida_name.SN_NOCHECK)

            tasks = find_task_desc_tbl(func_start, func_end)

            if (not tasks):
                shannon_generic.DEBUG("[d] find_task_desc_tbl() failed with None\n")
                return

            if (tasks > 0):
                idc.msg("[i] identified %d tasks\n" % tasks)
            else:
                idc.msg("[e] failed to identify tasks\n")

            for xref in idautils.XrefsTo(func_start, 0):

                pal_init_addr = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)

                if (pal_init_addr != idaapi.BADADDR):
                    idc.msg("[i] pal_Init(): %x\n" % pal_init_addr)
                    ida_name.set_name(pal_init_addr, "pal_Init", ida_name.SN_NOCHECK)

                    metrics = shannon_generic.get_metric(pal_init_addr)

                    for branch in metrics[6]:
                        first_operand = idc.get_operand_value(branch, 0)
                        validate_if_dm_trace_log(first_operand)

                    return
    return

def validate_if_dm_trace_log(bl_target):

    metrics = shannon_generic.get_metric(bl_target)
    #shannon_generic.print_metrics(bl_target, metrics)

    # this function has an insane amount of xrefs, very unique
    if (len(metrics[4]) > 150000):
        idc.msg("[i] dm_TraceMsg(): %x\n" % bl_target)
        ida_name.set_name(bl_target, "dm_TraceMsg", ida_name.SN_NOCHECK)

# find task descriptor table for newer devices, 5G and up
def find_task_desc_tbl_5g(task_func_start, task_func_end):

    idc.msg("[i] table discovery failed, attemping discovery for 5G modems\n")

    task_func_cur = task_func_start

    while (1):

        task_func_cur = idc.next_head(task_func_cur)
        task_opcode = ida_ua.ua_mnem(task_func_cur)

        # bailout
        if (task_func_cur >= task_func_end):
            idc.msg("[e] find_task_desc_tbl_5g(): end reached at %x, no table found\n" %
                    (task_func_cur))

            # let's try it one more time with another logic
            return find_task_desc_tbl_pixel(task_func_start, task_func_end)

        if (task_opcode == None):
            continue

        if ("BL" in task_opcode):

            xref = next(idautils.CodeRefsFrom(task_func_cur, 0))
            task_list_opcode = ida_ua.ua_mnem(xref)

            if ("MOV" in task_list_opcode):

                ida_name.set_name(xref, "pal_getTaskTbl", ida_name.SN_NOCHECK)

                target_ref = idc.get_operand_value(xref, 1)

                if (target_ref == None or target_ref == 0x0):
                    idc.msg("[e] cannot get operand 1 at %x\n" % xref)
                    continue

                #tbl_offset = int.from_bytes(target_ref, "little")

                ida_name.set_name(target_ref, "pal_TaskDescTbl", ida_name.SN_NOCHECK)

                if (target_ref != idaapi.BADADDR and target_ref != 0x0):

                    #target_ref = target_ref + 0X28

                    idc.msg("[i] pal_TaskDescTbl(): %x\n" % target_ref)

                    #these are longer, so start later
                    tasks = identify_task_init_start(target_ref)

                    return tasks

                else:

                    return -1


# we look for the first function call after the Task string and check for the first MOVW which
# loads the task table mostly hidden in a scatter part

# TODO: check if I can merge this with the above somehow, diff ebtween this and above is that
# in this one we don't enter a function which we do above

def find_task_desc_tbl_pixel(task_func_start, task_func_end):

    idc.msg("[i] table discovery failed, attemping discovery for pixel like modems\n")

    task_func_cur = get_PALTskTm_ref()

    while (1):

        task_func_cur = idc.next_head(task_func_cur)
        task_opcode = ida_ua.ua_mnem(task_func_cur)

        # bailout
        if (task_func_cur >= task_func_end):
            idc.msg("[e] find_task_desc_tbl_pixel: end reached %x\n" % (task_func_cur))
            return -1

        if (task_opcode == None):
            continue

        if ("BL" in task_opcode):

            task_func_cur = idc.next_head(task_func_cur)
            task_opcode = ida_ua.ua_mnem(task_func_cur)

            if ("MOV" in task_opcode):

                target_ref = idc.get_first_dref_from(task_func_cur)

                if (target_ref != idaapi.BADADDR and target_ref != 0x0):

                    #target_ref = target_ref + 0x27
                    #pad_task_struct(0xcf)

                    idc.msg("[i] pal_TaskDescTbl: %x\n" % (target_ref))

                    return identify_task_init_start(target_ref)

            else:

                return -1

# step 6 - find the second LDR in the function. It is the TaskDescTbl
def find_task_desc_tbl(task_func_start, task_func_end):

    task_func_cur = task_func_start

    ldr_cnt = 0

    while (1):
        task_func_cur = idc.next_head(task_func_cur)
        task_opcode = ida_ua.ua_mnem(task_func_cur)

        # bailout
        if (task_func_cur >= task_func_end):
            return None

        # skip text chunks inside function
        if (task_opcode == None):
            #shannon_generic.DEBUG("[d] error finding pal_TaskDescTbl() at %x\n" % task_func_cur)
            continue

        if ("LDR" in task_opcode):

            if (ldr_cnt == 1):
                target_ref = idc.get_operand_value(task_func_cur, 1)
                tbl_offset = int.from_bytes(
                    ida_bytes.get_bytes(target_ref, 4), "little")

                seg_start = idc.get_segm_start(task_func_cur)

                shannon_generic.DEBUG(
                    "[d] find_task_desc_tbl: found table at %x but segment start is %x\n" % (tbl_offset, seg_start))

                # sanity check to limit false positives, especially with pixel modems
                if (tbl_offset < seg_start):
                    return find_task_desc_tbl_pixel(task_func_start, task_func_end)

                ida_name.set_name(
                    tbl_offset, "pal_TaskDescTbl", ida_name.SN_NOCHECK)

                if (tbl_offset != idaapi.BADADDR and ida_bytes.is_loaded(tbl_offset)):

                    idc.msg("[i] pal_TaskDescTbl(): %x\n" % tbl_offset)

                    tasks = identify_task_init_start(tbl_offset)

                    return tasks

                else:
                    return find_task_desc_tbl_5g(task_func_start, task_func_end)

            ldr_cnt += 1

# start function to avoid recruisve calls of find_struct_start
def identify_task_init_start(tbl_offset):

    tbl_offset = find_struct_start(tbl_offset, 0)
    identify_task_init(tbl_offset, 0)

# universal task struct finder
def identify_task_init(tbl_offset, padding):

    MAX_TASKS = 256
    tasks = 0
    threshold = 5

    if (not tbl_offset):
        idc.msg("[e] identify_task_init: unable to detect task struct start offset\n")
        return []

    tbl_offset_orig = tbl_offset

    struct_id = idc.get_struc_id("task_struct")
    struct_size = idc.get_struc_size(struct_id)

    sptr = shannon_structs.get_struct(struct_id)
    str_ptr = shannon_structs.get_offset_by_name(sptr, "task_name")
    entry_ptr = shannon_structs.get_offset_by_name(sptr, "task_entry")
    
    task_entries = []

    while (tasks < MAX_TASKS):

        ida_bytes.del_items(tbl_offset, 0, struct_size)

        ida_bytes.create_struct(tbl_offset, struct_size, struct_id)

        str_offset = int.from_bytes(ida_bytes.get_bytes(
            (tbl_offset + str_ptr), 4), "little")

        ida_bytes.create_strlit(str_offset, 0, ida_nalt.STRTYPE_C)

        task_name_str = idc.get_strlit_contents(str_offset)

        entry_offset = int.from_bytes(ida_bytes.get_bytes((tbl_offset + entry_ptr), 4), "little")

        # break early if we met an undefined entry
        if (entry_offset == 0x0):
            shannon_generic.DEBUG(
                "[d] identify_task_init(): tasks %d, entry_offset is %x, breaking\n" % (tasks, entry_offset))
            break

        # make sure we don't have many false positives here
        if (task_name_str and len(task_name_str) > 3 and entry_offset > 0xFFFF):
            
            task_entries.append([task_name_str, entry_offset])
            
        else:

            shannon_generic.DEBUG("[d] %x: corrupt task struct\n" % entry_offset)
            break

        tbl_offset += struct_size

        tasks += 1

    # sanity check
    if (padding > 0xFFFF):
        return []

    if (tasks < threshold):

        padding += 1

        shannon_generic.DEBUG("[d] testing padding of %x, ssz: %d (found %d)\n" %
                              (padding, struct_size, tasks))

        pad_task_struct(padding)

        task_entries = identify_task_init(tbl_offset_orig, padding)

    if (len(task_entries) > threshold):
        for task in task_entries:
            
            if (not idc.is_code(idc.get_full_flags(entry_offset))):
                ida_ua.create_insn(entry_offset)

            #check again, if no code, realign
            if (not idc.is_code(idc.get_full_flags(entry_offset))):
                entry_offset = entry_offset - 1  # thumb
                ida_ua.create_insn(entry_offset)

            # realign function if needed
            task_entry_func_start = idc.get_func_attr(entry_offset, idc.FUNCATTR_START)

            if (task_entry_func_start != idaapi.BADADDR):
                shannon_funcs.function_find_boundaries(task_entry_func_start)
    
            idc.msg("[i] found task init for %s at %x\n" % (str(task[0].decode()), task[1]))

            ida_name.set_name(task[1], "pal_TaskInit_" + str(task[0].decode()), ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        
        # list of tasks is consumed, return empty to avoid multi procession in recurse
        return []

    return task_entries


#for debugging purpose export SHANNON_WORKFLOW="NO"
if (os.environ.get('SHANNON_WORKFLOW') == "NO"):
    idc.msg("[i] running pal reconstruct in standalone mode\n")
    find_pal_msg_funcs()
    find_pal_init()

#!/bin/python3

# Samsung Shannon Modem MPU Processor
# This script is automatically executed by the loader
# Alexander Pick 2024

import idc
import idaapi
import ida_name
import ida_ua
import ida_search
import ida_segment
import ida_bytes
import ida_struct

import shannon_generic

def find_hw_init():

    regex = "Invalid warm boot!!"

    # search only in main to avoid unnecessary long runtimes
    seg_t = ida_segment.get_segm_by_name("MAIN_file")
    seg_start = seg_t.start_ea
    seg_end = seg_t.end_ea - seg_t.start_ea

    offset = ida_search.find_text(
        seg_start, seg_end, 0, regex, ida_search.SEARCH_DOWN)

    if (offset != idaapi.BADADDR):

        hw_init_addr = idc.get_func_attr(offset, idc.FUNCATTR_START)
        idc.msg("[i] hw_Init(): %x\n" % hw_init_addr)
        ida_name.set_name(hw_init_addr, " hw_Init", ida_name.SN_NOCHECK)

        # check bounderies
        func_start = idc.get_func_attr(hw_init_addr, idc.FUNCATTR_START)
        func_end = idc.get_func_attr(hw_init_addr, idc.FUNCATTR_END)

        if (func_start != idaapi.BADADDR and func_end != idaapi.BADADDR):

            func_cur = func_start

            candidates = []

            while (1):
                func_cur = idc.next_head(func_cur)
                opcode = ida_ua.ua_mnem(func_cur)

                # bailout
                if (opcode == None):
                    continue

                if ("BL" in opcode):
                    bl_target = idc.get_operand_value(func_cur, 0)

                    candidates.append(bl_target)

                if (func_cur >= func_end):
                    break

            # unique
            candidates = list(set(candidates))

            for candidate in candidates:
                #idc.msg("[d] possible mpu function: %x\n" % candidate)
                validate_mpu_candidate(candidate)

# check if we found the mpu table
def validate_mpu_candidate(bl_target):

    metrics = shannon_generic.get_metric(bl_target)
    
    #shannon_generic.print_metrics(bl_target, metrics)

    # exact metric:
    # loops: 1 branch: 3 length: 32 basic blocks: 5 xrefs: 1 ldr: 6 calls: 7
    # loops: 2 branch: 4 length: 53 basic blocks: 7 xrefs: 1 ldr: 6 calls: 8

    if (len(metrics[0]) > 0 and len(metrics[0]) < 3 and metrics[3] > 2 and metrics[2] < 64 and len(metrics[4]) == 1 and len(metrics[6]) > 6):
        idc.msg("[i] hw_MpuInit(): %x\n" % bl_target)
        ida_name.set_name(bl_target, " hw_MpuInit", ida_name.SN_NOCHECK)

        process_mpu_table(metrics[5])

    # if there are 250+ refs to the candidate function it is the exception handler
    if (len(metrics[4]) > 250 and metrics[2] < 24):
        idc.msg("[i] hw_ExceptionHandler(): %x\n" % bl_target)
        ida_name.set_name(bl_target, " hw_ExceptionHandler",
                          ida_name.SN_NOCHECK)

# identifies the mpu tabl and processes it
def process_mpu_table(tbl_candidates):
    for ldr in tbl_candidates:
        if(ldr > 0x1000):
            mpu_tbl = int.from_bytes(ida_bytes.get_bytes(ldr, 4), "little")
            idc.msg("[i] mpu tbl candidate at %x\n" % mpu_tbl)

            struct_id = ida_struct.get_struc_id("mpu_region")
            struct_size = ida_struct.get_struc_size(struct_id)
            sptr = ida_struct.get_struc(struct_id)

            while(1):
                ida_bytes.del_items(mpu_tbl, 0,  struct_size)
                ida_bytes.create_struct(mpu_tbl, struct_size, struct_id)
                

                num_ptr = ida_struct.get_member_by_name(sptr, "num")
                addr_ptr = ida_struct.get_member_by_name(sptr, "addr")
                size_ptr = ida_struct.get_member_by_name(sptr, "size")

                xn_ptr = ida_struct.get_member_by_name(sptr, "size")

                num = int.from_bytes(ida_bytes.get_bytes(mpu_tbl+num_ptr.soff, 4), "little")
                addr = int.from_bytes(ida_bytes.get_bytes(mpu_tbl+addr_ptr.soff, 4), "little")
                size = int.from_bytes(ida_bytes.get_bytes(mpu_tbl+size_ptr.soff, 4), "little")

                if(num == 0xff):
                    idc.msg("[i] reached end of mpu tbl at %x\n" % mpu_tbl)
                    return

                xn = int.from_bytes(ida_bytes.get_bytes(mpu_tbl+xn_ptr.soff, 4), "little")

                seg_type = "CODE"
                if(xn > 0):
                    seg_type = "DATA"

                shannon_generic.add_memory_segment(addr, size, "MPU_"+str(num), seg_type, 0)
                
                mpu_tbl += struct_size
#!/bin/python3

# Samsung Shannon Modem Loader - MPU Processor
# This script is automatically executed by the loader
# Alexander Pick 2024

import idc
import idaapi
import ida_name
import ida_ua
import ida_segment
import ida_bytes
import ida_struct
import idautils

import shannon_generic
import shannon_funcs

import os

def get_segment_boundaries(seg_name="MAIN_file"):
        
    seg_t = ida_segment.get_segm_by_name(seg_name)

    if (seg_t.end_ea == idaapi.BADADDR):
        idc.msg("[e] cannot find "+seg_name+" boundaries\n")
        return None
    
    return seg_t

# find the hardware init function
def find_hw_init():

    idc.msg("[i] trying to find hw_init() and rebuild mpu\n")

    # search only in main to avoid unnecessary long runtimes
    seg_t = get_segment_boundaries()

    if(seg_t == None):
        return

    offset = shannon_generic.search_text(seg_t.start_ea, seg_t.end_ea, "Invalid warm boot")
    
    if (offset == idaapi.BADADDR):
        idc.msg("[e] hw_Init(): cannot find string\n")
        return
    
    offset = shannon_generic.get_first_ref(offset)

    # idc.msg("[d] find_hw_init() offset pre: %x\n" % offset)

    if (offset != idaapi.BADADDR):
        if (shannon_funcs.function_find_boundaries(offset)):
            offset = idc.get_func_attr(offset, idc.FUNCATTR_START)

    # idc.msg("[d] find_hw_init() offset: %x\n" % offset)

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
    else:
        idc.msg("[i] failed to identify hw_init()\n")

# this tries to find the MRC opcodes required for setting up the MMU
# we are looking for a write to SCTLR
def validate_mmu_candidate(bl_target):
    
    func_start = idc.get_func_attr(bl_target, idc.FUNCATTR_START)
    func_end = idc.get_func_attr(bl_target, idc.FUNCATTR_END)
    
    addr = func_start
    
    if(func_start != idaapi.BADADDR):
        
        while(addr <= func_end):
                        
            # First opcode is an MRC 
            opcode = ida_ua.ua_mnem(addr)
            
            if(opcode == None):
                addr = idc.next_head(addr)
                continue
            
            # SCTLR (c1, c0, 0) - System Control Register - core system controls <- want this
            # ACTLR (c1, c0, 1) - Auxiliary Control Register - coprocessor optimizations
            # CPACR (c1, c0, 2) - Coprocessor Access Control Register - access perm, FPU, NEON
            # NSACR (c1, c0, 7) - Non-Secure Access Control Register

            # MCR p15, 0, R0, c2, c0, 2 
            # -> Write to CP15 - Operand Num (normally 0), Source Reg CPU, Coproc Num, Coproc Reg, Reg Offset
            # c2 is translation table
            
            # MCR p15, 0, R1, c3, c0, 0 

            # MCR - write
            # MRC - read
            if ("MCR" in opcode):
                
                # workaround since get_oeprand_value does not work    
                t = idaapi.generate_disasm_line(addr)
                if(t):
                                        
                    operands_str = idaapi.tag_remove(t)
                    operands = operands_str.replace(",", "").split()
                                        
                    # CP15, the system control coprocessor is adressed
                    if("p15" in operands[1]):
                        
                        # c2, c0 
                        if("c2c0" in operands[3] and operands[4] == "0"):
                            
                            idc.msg("[i] TTBR0 setup at %x\n" % (addr))
                            idc.msg("[d] %s\n" % (operands_str))

                        if("c2c0" in operands[3] and operands[4] == "1"):
                            
                            idc.msg("[i] TTBR1 setup at %x\n" % (addr))
                            idc.msg("[d] %s\n" % (operands_str))
                            
            addr = idc.next_head(addr)

    return

# find all MRC with write to CP15 etc. - looking for MMU setup
def scan_for_mrc(target_seg="MAIN_file"):
        
    seg_t = get_segment_boundaries(target_seg)
    
    if(seg_t == None):
        return
        
    for ea in idautils.Functions(seg_t.start_ea, seg_t.end_ea):
        validate_mmu_candidate(ea)

    # idc.msg("[d] scan done\n")

# check if we found the mpu table
def validate_mpu_candidate(bl_target):

    metrics = shannon_generic.get_metric(bl_target)

    # enable metrics debug output
    #shannon_generic.print_metrics(bl_target, metrics)

    # metrics:
    # 0 loops (list)    1 or 2
    # 1 branch (list)
    # 2 length          32-70
    # 3 basicblocks     > 4
    # 4 xrefs (list)    always 1
    # 5 ldr (list)      6 or more
    # 6 calls (list)    6 or more

    # sample metric:
    # loops: 2 branch: 4 length: 53 basic blocks: 7 xrefs: 1 ldr: 6 calls: 8 (moto-training)
    # loops: 2 branch: 6 length: 70 basic blocks: 9 xrefs: 1 ldr: 16 calls: 9 (eng)

    # false
    # loops: 2 branch: 5 length: 74 basic blocks: 10 xrefs: 1 ldr: 14 calls: 9

    if ((len(metrics[0]) > 0 and len(metrics[0]) < 3) and metrics[3] > 4 and (metrics[2] > 24 and metrics[2] < 72)
            and len(metrics[4]) == 1 and len(metrics[6]) > 5 and (len(metrics[5]) > 5)):

        if (process_mpu_table(metrics[5])):
            # @tocheck: if any false positive occures, need to valdiate branches for calls to enable/disable
            idc.msg("[i] hw_MpuInit(): %x\n" % bl_target)
            ida_name.set_name(bl_target, " hw_MpuInit", ida_name.SN_NOCHECK)

    # if there are 250+ refs to the candidate function it is the exception handler or get_chip_name
    if (len(metrics[4]) > 250 and (metrics[2] > 24 and metrics[2] < 80)):
        idc.msg("[i] hw_SwExceptionHandler(): %x\n" % bl_target)
        ida_name.set_name(bl_target, " hw_SwExceptionHandler", ida_name.SN_NOCHECK)

    # commonly just an LDR but behaves wonky across versions, so disabled atm
    # if (len(metrics[4]) > 200 and metrics[2] < 3):
    #     idc.msg("[i] get_chip_name(): %x\n" % bl_target)
    #     ida_name.set_name(bl_target, " get_chip_name", ida_name.SN_NOCHECK)

def is_main_segment(addr):

    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    if (addr > seg_t.start_ea and addr < seg_t.end_ea):
        return True
    else:
        return False

# identifies the mpu tabl and processes it
def process_mpu_table(tbl_candidates):

    for ldr in tbl_candidates:

        if (ldr > 0x1000):
            mpu_tbl = int.from_bytes(ida_bytes.get_bytes(ldr, 4), "little")
            idc.msg("[i] mpu tbl candidate at %x\n" % mpu_tbl)

            # prevents false positives
            if (not is_main_segment(mpu_tbl)):
                idc.msg("[e] candidate outside boundaries\n")
                return False

            struct_id = ida_struct.get_struc_id("mpu_region")
            struct_size = ida_struct.get_struc_size(struct_id)
            sptr = ida_struct.get_struc(struct_id)

            # just a sanity check in case we hit the wrong place
            # Shannon mpu table is never amazingly big
            max_entries = 0x20
            entries = 0

            while (1):

                ida_bytes.del_items(mpu_tbl, 0, struct_size)
                ida_bytes.create_struct(mpu_tbl, struct_size, struct_id)

                num_ptr = ida_struct.get_member_by_name(sptr, "num")
                addr_ptr = ida_struct.get_member_by_name(sptr, "addr")
                size_ptr = ida_struct.get_member_by_name(sptr, "size")

                xn_ptr = ida_struct.get_member_by_name(sptr, "size")

                num = int.from_bytes(ida_bytes.get_bytes(mpu_tbl + num_ptr.soff, 4), "little")
                addr = int.from_bytes(ida_bytes.get_bytes(mpu_tbl + addr_ptr.soff, 4), "little")
                size = int.from_bytes(ida_bytes.get_bytes(mpu_tbl + size_ptr.soff, 4), "little")

                if (num == 0xff):
                    idc.msg("[i] reached end of mpu tbl at %x\n" % mpu_tbl)
                    return True

                if (entries == max_entries):
                    idc.msg("[e] too many entries in table at %x\n" % mpu_tbl)
                    return False

                xn = int.from_bytes(ida_bytes.get_bytes(
                    mpu_tbl + xn_ptr.soff, 4), "little")

                seg_type = "CODE"

                if (xn > 0):
                    seg_type = "DATA"

                shannon_generic.add_memory_segment(
                    addr, size, "MPU_" + str(num), seg_type, 0)

                mpu_tbl += struct_size
                entries += 1

    return True


#for debugging purpose export SHANNON_WORKFLOW="NO"
if os.environ.get('SHANNON_WORKFLOW') == "NO":
    idc.msg("[i] running mpu in standalone mode\n")
    find_hw_init()

#scan_for_mrc()
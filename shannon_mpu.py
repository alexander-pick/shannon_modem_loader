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

import ida_idp

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

# comment mrc and mrc operations
def comment_mcr_mrc(read_write, operand, opcode, addr):
    
    op = "read"
    
    if(read_write):
        op = "write"

    # ID and System Configuration Registers
    if("c0c" in operand):
        idaapi.set_cmt(addr, "Information about the processor - "+op, 0)

        if(opcode == 0):
            idaapi.set_cmt(addr, "Main ID Register (MIDR) - processor identification information - "+op, 0)
            return

        if(opcode == 1):
            idaapi.set_cmt(addr, "Cache Type Register (CTR) - level 1 data cache characteristics - "+op, 0)
            return
    
        if(opcode == 2):
            idaapi.set_cmt(addr, "Information about TCMs (Tightly Coupled Memories) - "+op, 0)
            return
        
        if(opcode == 3):
            idaapi.set_cmt(addr, "Information about the TLB architecture - "+op, 0)
            idc.msg("[i] MMU - TLB info request at %x\n" % (addr))
            return
    
        if(opcode == 4):
            idaapi.set_cmt(addr, "Information about the MPU (Memory Protection Unit) - "+op, 0)
            idc.msg("[i] MMU - MMU info request at %x\n" % (addr))
            return
        
        if(opcode == 5):
            idaapi.set_cmt(addr, "Processor Feature Register 1 (PFR1) - additional processor feature information - "+op, 0)
            return
        
        if(opcode == 6):
            idaapi.set_cmt(addr, "Processor Feature Register 1 (PFR1) - additional processor feature information - "+op, 0)
            return
        
        if(opcode == 7):
            idaapi.set_cmt(addr, "Debug Feature Register (DFR) - information about debug features - "+op, 0)
            return
        
        if(opcode == 8):
            idaapi.set_cmt(addr, "Auxiliary Feature Register (AFR) - auxiliary features information - "+op, 0)
            return
        
        if(opcode == 9):
            idaapi.set_cmt(addr, "Memory Model Feature Register 0 (MMFR0) - additional memory model features. - "+op, 0)
            return
        
        if(opcode == 10):
            idaapi.set_cmt(addr, "Memory Model Feature Register 1 (MMFR1) - additional memory model features. - "+op, 0)
            return
        
        if(opcode == 11):
            idaapi.set_cmt(addr, "Memory Model Feature Register 2 (MMFR2) - additional memory model features. - "+op, 0)
            return
        
        if(opcode == 12):
            idaapi.set_cmt(addr, "Memory Model Feature Register 3 (MMFR3) - additional memory model features. - "+op, 0)
            return

        if(opcode == 13):
            idaapi.set_cmt(addr, "ISA Feature Register 0 (ISAR1) - additional instruction set information - "+op, 0)
            return
        
        if(opcode == 14):
            idaapi.set_cmt(addr, "ISA Feature Register 1 (ISAR1) - additional instruction set information - "+op, 0)
            return
        
        if(opcode == 15):
            idaapi.set_cmt(addr, "ISA Feature Register 2 (ISAR2) - additional instruction set information - "+op, 0)
            return
            
    # System Control Register (SCTLR)
    if("c1c" in operand):
        idaapi.set_cmt(addr, "System Control Register - "+op, 0)
        return

    # Translation Table Base Register (TTBR)
    if("c2c" in operand):
        idaapi.set_cmt(addr, "Translation Table Base Register - "+op, 0)
       
        if(opcode == 0):
            idaapi.set_cmt(addr, "Translation Table Base Register (TTBR0), base of the first-level translation table - "+op, 0)
            if(read_write):
                idc.msg("[i] MMU - TTBR0 write at %x\n" % (addr))            
            return   
    
        if(opcode == 1):
            idaapi.set_cmt(addr, "Translation Table Base Register (TTBR1), base of the second-level translation table - "+op, 0)
            if(read_write):
                idc.msg("[i] MMU - TTBR1 write at %x\n" % (addr))
            return   
    
        if(opcode == 2):
            idaapi.set_cmt(addr, "Translation Table Base Control Register (TTBCR), controls the use of TTBR0 and TTBR1 - "+op, 0)
            idc.msg("[i] MMU - TTBCR operation at %x\n" % (addr))
            return                       

    # Domain Access Control Register
    if("c3c" in operand):
        idaapi.set_cmt(addr, "Domain Access Control Register - "+op, 0)
        if(read_write):
            idc.msg("[i] MMU - DACR write at %x\n" % (addr))      
        return   

    # Fault Status Registers
    if("c5c" in operand):
        idaapi.set_cmt(addr, "Fault Status Registers - "+op, 0)
        return   
        
    # Fault Address Registers
    if("c6c" in operand):
        idaapi.set_cmt(addr, "Fault Address Registers - "+op, 0)
        return   
        
    # Cache and Branch Predictor Maintenance
    if("c7c" in operand):
        idaapi.set_cmt(addr, "Cache and Branch Predictor Maintenance - "+op, 0)
        return   
        
    # Performance Monitors Registers
    if("c9c" in operand):
        idaapi.set_cmt(addr, "Performance Monitors Registers - "+op, 0)
        return   

    # Memory Management Fault Address Registers
    if("c10c" in operand):
        idaapi.set_cmt(addr, "Memory Management Fault Address Registers - "+op, 0)
        return   
        
    # Vector Base Address Register (VBAR):
    if("c12c" in operand):
        idaapi.set_cmt(addr, "Vector Base Address Register (VBAR) - "+op, 0)
        return
    
    # Process, Context, and Thread ID Registers
    if("c13c" in operand):
        idaapi.set_cmt(addr, "Process, Context, and Thread ID Registers - "+op, 0)
        return

# comment MSR ops on CPSR
def comment_cpsr(value, addr):

    # convert
    binary_value = format(value, '032b')

    # extrat
    n_flag = int(binary_value[0], 2)
    z_flag = int(binary_value[1], 2)
    c_flag = int(binary_value[2], 2)
    v_flag = int(binary_value[3], 2)
    q_flag = int(binary_value[27], 2)
    j_flag = int(binary_value[24], 2)
    e_flag = int(binary_value[9], 2)
    a_flag = int(binary_value[8], 2)
    i_flag = int(binary_value[7], 2)
    f_flag = int(binary_value[6], 2)
    t_flag = int(binary_value[5], 2)
    
    mode_bits = binary_value[27:32]

    # map mode bits to mode names
    modes = {
        '10000': 'user mode',
        '10001': 'FIQ mode',
        '10010': 'IRQ mode',
        '10011': 'supervisor mode',
        '10111': 'abort mode',
        '11011': 'undefined mode',
        '11111': 'system mode',
    }
    mode = modes.get(mode_bits, 'Unknown mode')

    # the flags
    flags = {
        'N': 'negative',
        'Z': 'zero',
        'C': 'carry',
        'V': 'overflow',
        'Q': 'saturation',
        'J': 'jazelle',
        'E': 'endian',
        'A': 'asynchronous abort',
        'I': 'IRQ disable',
        'F': 'FIQ disable',
        'T': 'thumb',
    }

    comment = "mode: "+mode+"\n\n"
    comment += "flags\n"
    
    for bit, (name, description) in enumerate(flags.items(), start=31):
        
        comment += str(bit)+": " 
             
        if(eval(name.lower() + "_flag")):
            comment += "1 "+description+"\n"
        else:
            comment += "0 "+description+"\n"

    idaapi.set_cmt(addr, comment, 0)

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

            # MCR p15, 0, R0, c2, c0, 2 
            # -> Write to CP15 - Operand Num (normally 0), Source Reg CPU, Coproc Num, Coproc Reg, Reg Offset
            # c2 is translation table
            
            # MCR - write
            # MRC - read
            
            if("MSR" in opcode):
                
                cpsr = idc.get_operand_value(addr, 0)
                cpsr_value = idc.get_operand_value(addr, 1)

                if (cpsr == -1):
                    addr = idc.next_head(addr)
                    continue

                cpsr_str = ida_idp.get_reg_name(cpsr, 0)

                # this is normally a bit field, we just analyse some very common values here
                if ("CPSR" in cpsr_str):
                    comment_cpsr(cpsr_value, addr)
                                    
            if("MCR" == opcode or "MRC" == opcode):
                
                #idc.msg("[d] MCR/MRC: %x\n" % addr) 
            
                # workaround since get_oeprand_value does not work    
                t = idaapi.generate_disasm_line(addr)
                if(t):
                                        
                    operands_str = idaapi.tag_remove(t)
                    operands = operands_str.replace(",", "").replace(";","").split()
                    
                    #idc.msg("[d] %s\n" % operands_str) 

                    # CP15, the system control coprocessor is adressed
                    if("p15" in operands[1]):
                        
                        if(len(operands) < 5):
                            idc.msg("[i] MCR/MRC operands error at %x\n" % addr)
                            addr = idc.next_head(addr)
                            continue
            
                        if ("MCR" in opcode):
                            comment_mcr_mrc(True, operands[3], int(operands[4]), addr)  
                        
                        else:
                            
                            comment_mcr_mrc(False, operands[3], int(operands[4]), addr)            
   
            addr = idc.next_head(addr)

    return

# find all MRC with write to CP15 etc. - looking for MMU setup
def scan_for_mrc(target_seg="MAIN_file"):
    
    idc.msg("[i] trying to identify MMU related opcodes in %s\n" % target_seg) 
        
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

scan_for_mrc()
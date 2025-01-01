#!/bin/python3

# Samsung Shannon Modem Loader
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024-2025

import idc
import ida_segment
import ida_ua

import os

import shannon_generic

max_ops = 6
ref_segs = 0

def find_mov(ea, reg, memn):
    
    global max_ops
    cnt = 0
    ret = -1
    
    while cnt < max_ops:
        
        ea = idc.prev_head(ea)
        opcode = ida_ua.ua_mnem(ea)
        
        if (opcode == None):
            continue
        
        if (memn in opcode):
            
            op_0_t = idc.get_operand_type(ea, 0)
            
            if(op_0_t == ida_ua.o_reg):
                op_0 = idc.get_operand_value(ea, 0)
                op_1 = idc.get_operand_value(ea, 1)
                if(op_0 == reg):
                    return op_1
                else:
                    shannon_generic.DEBUG("[d] find_mov(): reg mismatch at %x\n" % ea)
    
            else:
                shannon_generic.DEBUG("[d] find_mov(): type mismatch at %x\n" % ea)
    
        cnt += 1
        
    return ret

# deals with indirect reference produced by more recent versions of compiler rvct, 
# these references consist of a movw, movt and a ldr/str on the [reg]

def scan_main_indirect_refs():
    
    global ref_segs
    
    found_refs = 0
    
    idc.msg("[i] searching and adding indirect xrefs in MAIN\n")

    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    addr = seg_t.start_ea

    while (addr < seg_t.end_ea):
        
        addr = idc.next_head(addr)

        if (idc.is_code(idc.get_full_flags(addr))):

            opcode = ida_ua.ua_mnem(addr)

            if (opcode == None):
                continue

            if ("LDR" == opcode or "STR" == opcode):
                
                insn = ida_ua.insn_t()
                inslen = ida_ua.decode_insn(insn, addr)
                if(inslen == 0):
                    continue
                
                op = insn.ops[1]
                
                # see documentation for op_t::o_phrase why addr is ""
                # op.phrase -> reg num
                # op.type = 3 (with only one reg)
                # 0xd -> SP
                
                if((op.addr == 0) and (op.phrase != 0xD) and (op.specflag1 == 0) and (op.type == 4)):
                    
                    #print("[d] found indirect ldr at %x: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x -> %s" % 
                    # (addr, op.n, op.type, op.offo, op.flags , op.reg, op.dtype, op.phrase, op.value, op.specval, 
                    # op.value, op.value64, op.specflag1, op.specflag2, op.specflag3, op.specflag4,
                    # idc.generate_disasm_line(addr, 0)))
                
                    high = find_mov(addr, op.reg, "MOVT")
                    low = find_mov(addr, op.reg, "MOVW")
    
                    if(high != -1 and low != -1):
                        
                        shannon_generic.DEBUG("[d] found indirect at %x: %s\n" % (addr, idc.generate_disasm_line(addr, 0)))
                        
                        target = high << 16
                        target |= low
                        
                        shannon_generic.DEBUG("[d] %x: found xref to %x\n" % (addr, target))
                        
                        if(idc.get_segm_name(target) == ''):
                            
                            seg_start = target & 0xFFFF0000
                            seg_len =  0xFFFF
                            
                            seg_name = idc.get_segm_name(seg_start)                            
                            
                            if(seg_name != ''):
                                 
                                seg_t_i = ida_segment.get_segm_by_name(seg_name)
                                 
                                seg_start = seg_t_i.end_ea + 1
                                diff = seg_start - (target & 0xFFFF0000)
                                 
                                seg_len -= diff 
                                
                                shannon_generic.DEBUG("[d] creating segment at %x with diff of %d, new len %d\n" % (seg_start, diff, seg_len))
                            
                            shannon_generic.add_memory_segment(seg_start, seg_len, "ref_"+str(ref_segs), seg_type="DATA")
                            ref_segs += 1                            
                            
                        idc.add_dref(addr, target, idc.XREF_USER | idc.dr_O)
                        idc.set_cmt(addr, ("TW XREF: %x" % target), 0)
                        
                        found_refs += 1

    idc.msg("[i] added %d references\n" % found_refs)

#for debugging purpose export SHANNON_WORKFLOW="NO"
if (os.environ.get('SHANNON_WORKFLOW') == "NO"):
    idc.msg("[i] running mpu in standalone mode\n")
    scan_main_indirect_refs()

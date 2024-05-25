#!/bin/python3

# Samsung Shannon Modem Postprocessor
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024

import idc
import idaapi
import idautils
import ida_idp
import ida_bytes
import ida_name
import ida_idp
import ida_segment
import ida_ua
import ida_funcs
import ida_struct
import ida_nalt
import ida_name

import re

import shannon_pal_reconstrutor as pal_re

class idb_finalize_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    # this creates cmts from previously created dbt structures to anote 
    # functions with their source paths and string refs
    def make_dbt_refs(self):

        struct_id = ida_struct.get_struc_id("dbt_struct")
        all_structs = idautils.XrefsTo(struct_id, 0)
        sptr = ida_struct.get_struc(struct_id)

        for i in all_structs:           
                
            str_ptr = ida_struct.get_member_by_name(sptr, "msg_ptr")
            str_offset = int.from_bytes(ida_bytes.get_bytes(i.frm+str_ptr.soff, 4), "little")
            # creating is mostly not needed but we do it to make sure it is defined
            ida_bytes.create_strlit(str_offset, 0, ida_nalt.STRTYPE_C)
            msg_str = idc.get_strlit_contents(str_offset)
            #print("%x: %s" % (str_offset, msg_str))

            file = ida_struct.get_member_by_name(sptr, "file")
            file_offset = int.from_bytes(ida_bytes.get_bytes(i.frm+file.soff, 4), "little")
            ida_bytes.create_strlit(file_offset, 0, ida_nalt.STRTYPE_C)
            file_str = idc.get_strlit_contents(file_offset)
            #print("%x: %s" % (file_offset, file_str))

            #find xref to struct
            for xref_dbt in idautils.XrefsTo(i.frm,  0):
                if(msg_str != None):
                    idaapi.set_cmt(xref_dbt.frm, msg_str.decode(), 1)

                    func_start = idc.get_func_attr(xref_dbt.frm, idc.FUNCATTR_START)

                    if(func_start !=  idaapi.BADADDR):
                        if(file_str != None):
                            idaapi.set_func_cmt(func_start, file_str.decode(), 1)

    def resolve_ref(self, str_addr):

        func_name = None
        str_offset = int.from_bytes(ida_bytes.get_bytes(str_addr, 4), "little")
        # print("[d] %x: fallback ref" % str_offset)
        
        func_name = idc.get_strlit_contents(str_offset)
        # yes it's a ref to a string
    
        if(func_name != None):
            return func_name
        else:
            return None
    
    def function_exists(self, name):
        
        for addr in idautils.Functions():
        
            func_name = idc.get_func_name(addr)
            
            if func_name == name:
                return True
        
        return False
    
    # deal with dupes in some modems
    def function_find_name(self,name):
        postfix = 0
        orig_name = name
        while(self.function_exists(name) == True):
            if(postfix > 0):
                name = orig_name + "_" + str(postfix)
            postfix += 1
            # sanity check
            if(postfix > 42):
                break
        #filter some bad chars before returning the string
        return name.translate(dict.fromkeys(map(ord, u",~")))
    
    def create_name(self, ea, name):
        for xref in idautils.XrefsTo(ea, 0):
            func_start = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
                
            if(func_start !=  idaapi.BADADDR):
                if(len(name) > 8):
                    ida_name.set_name(func_start, self.function_find_name(name), ida_name.SN_NOCHECK | ida_name.SN_FORCE)
                else:
                    print("[e] %x: function name too short: %s" % (func_start, name)) 
    
    def restore_cpp_names(self):

        sc = idautils.Strings()

        for i in sc:
            # step 1 - find a function name
            regex = "([a-z]*::[A-Za-z_]*::[A-Za-z_]*)"

            if(re.match(regex, str(i))):
                self.create_name(i.ea, str(i))


    # restores the function names of SS related functions from a macro created function structure
    def restore_ss_names(self):

        sc = idautils.Strings()

        for i in sc:
            # step 1 - find a function name
            if(str(i) == "ss_DecodeGmmFacilityMsg"):
                # step 2 - find xrefs to this name, essentially should be just one xref
                for xref in idautils.XrefsTo(i.ea, 0):

                    # sanity check - validate that xref target is a function, or next
                    if(idc.get_func_attr(xref.frm, idc.FUNCATTR_START) ==  idaapi.BADADDR):
                        continue
                    # step 3 - iterate over the next instructions until we find a function call

                    xref_str = None
                    tries = 0
                    prev_offset = xref.frm

                    while(tries < 5):
                        # forward search, max 5 instructions
                        xref_str_tmp = idc.next_head(prev_offset)
                        opcode = ida_ua.ua_mnem(xref_str_tmp)
                        if(opcode == "BL"):
                            # print("[d] found BL at %x" % xref_str_tmp)
                            # docs said this is a list, but seems to be a generator?
                            xref_str = next(idautils.CodeRefsFrom(xref_str_tmp,  0))
                            break
                        else:
                            prev_offset = xref_str_tmp
                            tries += 1


                    if(xref_str == None):
                        continue # abort if not foudn or emptyt list

                    print("[i] found verbose ss_ name function: %x" % xref_str)

                    # step 4 - iterate over the all calls to this function
                    for xref_func in idautils.XrefsTo(xref_str,  0):

                            tries = 0
                            prev_offset = xref_func.frm

                            while(tries < 5):
                                cur_offset = idc.prev_head(prev_offset)
                                opcode = ida_ua.ua_mnem(cur_offset)
                                if(opcode == "LDR"):
                                    # print("[d] found LDR at %x" % cur_offset)
                                    break
                                else:
                                    prev_offset = cur_offset
                                    tries += 1

                            #get LDR param which is the function name
                            str_addr = idc.get_operand_value(cur_offset, 1)

                            #read string
                            func_name = idc.get_strlit_contents(str_addr)

                            # sanity checks
                            if(func_name == None):
                                # print("[d] %x: failed sanity check (None)" % str_addr)
                                check_failed = 1
                            # this in elif to avoid err with undefined bla
                            elif(len(func_name.decode()) < 8):
                                # print("[d] %x: failed sanity check (length)" % str_addr)
                                check_failed = 1

                            if check_failed:
                                # try to resolve ref
                                func_name = self.resolve_ref(str_addr)

                                if(func_name == None):
                                    print("[e] %x: function name not defined" % str_addr)
                                    continue

                            func_name_str = func_name.decode()

                            #print("[d] %x: found function name %s" % (str_addr, func_name_str))
                            
                            if("ss_" not in func_name_str):
                                print("[e] %x: failed to find function name for %x, found '%s' instead" % (str_addr, xref_func.frm, func_name))
                                continue

                            #create a string at string offfset
                            ida_bytes.create_strlit(str_addr, 0, ida_nalt.STRTYPE_C)

                            func_start = idc.get_func_attr(xref_func.frm, idc.FUNCATTR_START)
                            #print(hex(func_start))

                            if(func_start !=  idaapi.BADADDR):

                                if(len(func_name_str) > 8):
                                    idaapi.set_name(func_start, self.function_find_name(func_name_str))
                                else:
                                    print("[e] %x: function name too short: %s" % (func_start, func_name_str)) 
                            else:
                                #print("not a function, searching for start")
                                cur_offset = xref_func.frm
                                prev_offset = 0
                                # find func boundaries
                                while 1:
                                    flags = idc.get_func_flags(cur_offset)
                                    opcode = ida_ua.ua_mnem(cur_offset)

                                    if(flags == -1 and opcode != None):
                                        prev_offset = cur_offset
                                        cur_offset = idc.prev_head(cur_offset)
                                    else:
                                        #print("FUNC_START ", hex(prev_offset))
                                
                                        ida_funcs.add_func(prev_offset,idc.prev_head(str_addr))
                                        idaapi.set_name(prev_offset, self.function_find_name(func_name_str))

    #helper function to set a name on the target of a LDR or B
    def get_ref_set_name(self, cur_ea, name):

        opcode = ida_ua.ua_mnem(cur_ea)
        #print("[d] %x: %s -> %s" % (cur_ea, opcode, name))
        if(opcode == "LDR"):
            target_ref = idc.get_operand_value(cur_ea, 1)
            target = int.from_bytes(ida_bytes.get_bytes(target_ref, 4), "little")
            ida_name.set_name(target, name, ida_name.SN_NOCHECK)
        if(opcode == "B"):
            target = idc.get_operand_value(cur_ea, 0)
            ida_name.set_name(target, name, ida_name.SN_NOCHECK)

    # creates strings which are at least 12 bytes long
    def create_long_strings(self):
        strings = idautils.Strings()

        strings.setup(strtypes=[ida_nalt.STRTYPE_C],
                    ignore_instructions=True, minlen=12)
        
        strings.refresh()
        
        for s in strings:
            #sanity check, is unknown bytes?
            if(idc.is_unknown(idc.get_full_flags(s.ea))):
                ida_bytes.create_strlit(s.ea, 0, ida_nalt.STRTYPE_TERMCHR)

    def add_memory_segment(self, seg_start, seg_size, seg_name):

        seg_end = seg_start + seg_size

        idc.add_segm_ex(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes,
                        idaapi.scPub, ida_segment.ADDSEG_SPARSE)

        idc.set_segm_class(seg_start, "DATA")
        idc.set_segm_type(seg_start, idaapi.SEG_DATA)
        idc.set_segm_name(seg_start, seg_name)

        # make sure it is really STT_MM (sparse)
        ida_bytes.change_storage_type(seg_start, seg_end, 1)

    def auto_empty_finally(self):

        idaapi.show_wait_box('HIDECANCEL\nPost-processing modem image, please wait...')

        pal_re.find_basic_pal_functions()

        self.restore_ss_names()
        self.restore_cpp_names()
        self.create_long_strings()
        self.make_dbt_refs()

        for s in idautils.Segments():
            
            seg_start= idc.get_segm_start(s)
            seg_name = idc.get_segm_name(seg_start)

            print("%x: %s" % (seg_start, seg_name))
            
            # add some names
            if(seg_name == "BOOT_file"):

                self.get_ref_set_name(seg_start, "start")

            if(seg_name == "MAIN_file"):
                
                self.get_ref_set_name(seg_start, "reset_v")
                self.get_ref_set_name(seg_start+4, "undef_inst_v")
                self.get_ref_set_name(seg_start+8, "soft_int_v")
                self.get_ref_set_name(seg_start+12, "prefetch_abort_v")
                self.get_ref_set_name(seg_start+16, "data_abort_v")
                self.get_ref_set_name(seg_start+24, "irq_v")

        # add additional memory ranges

        self.add_memory_segment(0x00000000, 0x000FFFFF, "ITCM_low")
        self.add_memory_segment(0x00100000, 0x0FEFFFFF, "EXTERNAL_1")
        # add_data_segment(0x04800000, 0x0000FFFF, "unkown_boot")
        # add_data_segment(0x04000000, 0x0001FFFF, "bootrom")

        self.add_memory_segment(0x10000000, 0x0000FFFF, "ITCM_high")
        self.add_memory_segment(0x10010000, 0x0FFEFFFF, "EXTERNAL_2")

        self.add_memory_segment(0x20000000, 0x000FFFFF, "SRAM_DTCM")
        # normally 0x1FEFFFFF, but shortened as only a fraction is used
        self.add_memory_segment(0x20100000, 0x1FEFFFFF, "SRAM_EXTERN")

        ida_name.set_name(0x32000000, "unknown_0", ida_name.SN_NOCHECK)

        # Normaly Pheriphials but this is used differently
        self.add_memory_segment(0x40000000, 0x1EFFFFFF, "AHBP")

        ida_name.set_name(0x44200000, "RAM", ida_name.SN_NOCHECK)
        ida_name.set_name(0x47F00000, "ABOX", ida_name.SN_NOCHECK)

        self.add_memory_segment(0x60000000, 0x3fffffff, "SRAM_EXTERN")

        ida_name.set_name(0x80000000, "unknown_1", ida_name.SN_NOCHECK)
        ida_name.set_name(0x81000000, "unknown_2", ida_name.SN_NOCHECK)
        ida_name.set_name(0x81002000, "unknown_3", ida_name.SN_NOCHECK)
        ida_name.set_name(0x84000000, "UART", ida_name.SN_NOCHECK)
        ida_name.set_name(0x85000000, "unknown_4", ida_name.SN_NOCHECK)
        ida_name.set_name(0x8F900000, "unknown_5", ida_name.SN_NOCHECK)
        ida_name.set_name(0x8FC30000, "USI_1", ida_name.SN_NOCHECK)
        ida_name.set_name(0x8FC22000, "USI_2", ida_name.SN_NOCHECK)
        ida_name.set_name(0x8FC60000, "USI_3", ida_name.SN_NOCHECK)
        ida_name.set_name(0x8FD20000, "USI_4", ida_name.SN_NOCHECK)

        ida_name.set_name(0xD0800000, "unknown_6", ida_name.SN_NOCHECK)

        ida_name.set_name(0xC1000000, "TWOG_1", ida_name.SN_NOCHECK)
        ida_name.set_name(0xC1001000, "TWOG_2", ida_name.SN_NOCHECK)
        ida_name.set_name(0xC1800000, "MARCONI_1", ida_name.SN_NOCHECK)
        ida_name.set_name(0xC2000000, "MARCONI_2", ida_name.SN_NOCHECK)
        ida_name.set_name(0xCE000000, "unknown_7", ida_name.SN_NOCHECK)

        self.add_memory_segment(0xA0000000, 0x3fffffff, "EXT_DEVICE")

        # 0xE0000000-0xFFFFFFFF - system level use
        self.add_memory_segment(0xE0000000, 0x1FFFFFFF, "SYSTEM")

        0xE06FA2CA

        # 0xE0000000-0xE00FFFFF - private peripheral bus (PPB)
        self.add_memory_segment(0xE0000000, 0x000FFFFF, "PPB")

        self.add_memory_segment(0xE0001000, 0x00000FFF, "PPB_DW")
        self.add_memory_segment(0xE0002000, 0x00000FFF, "PPB_BP")
        self.add_memory_segment(0xE000E000, 0x00000CFF, "PPB_NVIC")
        self.add_memory_segment(0xE000ED00, 0x000002FF, "PPB_DBGCTL")
        self.add_memory_segment(0xE0005000, 0x00000FFF, "PPB")
        self.add_memory_segment(0xE00FF000, 0x00000FFF, "ROM_TABLE")

        # 0xE000E000 to 0xE000EFFF - system control space (SCS)
        ida_name.set_name(0xE000E000, "system control space (SCS)", ida_name.SN_NOCHECK)

        # system level
        self.add_memory_segment(0xEC000000, 0x0000FFFF, "GLINK")

        self.add_memory_segment(0xF0000000, 0x0FFFFFFF, "unknown_8")

        for s in idautils.Segments():

            # reschedule everything for a last auto analysis pass
            idc.plan_and_wait(idc.get_segm_start(s),idc.get_segm_end(s))

        idaapi.hide_wait_box()

        return

idb_hooks = idb_finalize_hooks_t()
idb_hooks.hook()
idc.msg("[i] Shannon postprocessor scheduled.\n")

# for testing as script only
# idb_hooks.restore_ss_names()
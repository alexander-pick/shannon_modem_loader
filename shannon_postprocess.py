#!/bin/python3

# Samsung Shannon Modem Postprocessor
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024

import idc
import idaapi
import ida_idp
import ida_bytes
import ida_name
import ida_idp
import ida_segment
import idautils
import ida_ua
import ida_funcs
import ida_struct
import ida_nalt

class idb_finalize_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    # this creates cmts from previously created dbt structures to anote 
    # functions with their source paths and string refs
    def make_dbt_refs(self):

        struct_id = ida_struct.get_struc_id("dbt_struct")
        all_structs = idautils.XrefsTo(struct_id, 0)

        for i in all_structs:

            sptr = ida_struct.get_struc(struct_id)
                
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

    # restores the function names of SS related functions from a macro created function structure
    def restore_ss_names(self):

        sc = idautils.Strings()

        for i in sc:
            if(str(i) == "ss_DecodeGmmSsReleaseIndMsg"):
                # find xref to function name, essentially should be just one xref
                for xref in idautils.XrefsTo(i.ea, 0):  
                    for xref_str in idautils.CodeRefsFrom(idc.next_head(xref.frm),  0):
                        for xref_func in idautils.XrefsTo(xref_str,  0):
                            cur_offset = idc.prev_head(xref_func.frm)

                            while 1:
                                str_addr = idc.get_operand_value(cur_offset, 1)
                                #print(hex(str_addr))
                                func_name = idc.get_strlit_contents(str_addr)

                                if(func_name != None):
                                    # get what we see 
                                    opcode = ida_ua.ua_mnem(cur_offset)
                                    if(opcode == "NOP"):
                                        # if we hit the NOP, go forward again to realign
                                        cur_offset = idc.next_head(cur_offset)
                                    break
                                else:
                                    cur_offset = idc.prev_head(cur_offset)

                            #print(func_name.decode())

                            func_start = idc.get_func_attr(xref_func.frm, idc.FUNCATTR_START)
                            #print(hex(func_start))

                            if(func_start !=  idaapi.BADADDR):
                                idaapi.set_name(func_start, func_name.decode())
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
                                        idaapi.set_name(prev_offset, func_name.decode())
                                        break

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

        self.restore_ss_names()
        self.make_dbt_refs()

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

        ida_name.set_name(0x32000000, "unknown_0")

        # Normaly Pheriphials but this is used differently
        self.add_memory_segment(0x40000000, 0x1EFFFFFF, "AHBP")

        ida_name.set_name(0x44200000, "RAM")
        ida_name.set_name(0x47F00000, "ABOX")

        self.add_memory_segment(0x60000000, 0x3fffffff, "SRAM_EXTERN")

        ida_name.set_name(0x80000000, "unknown_1")
        ida_name.set_name(0x81000000, "unknown_2")
        ida_name.set_name(0x81002000, "unknown_3")
        ida_name.set_name(0x84000000, "UART")
        ida_name.set_name(0x85000000, "unknown_4")
        ida_name.set_name(0x8F900000, "unknown_5")
        ida_name.set_name(0x8FC30000, "USI_1")
        ida_name.set_name(0x8FC22000, "USI_2")
        ida_name.set_name(0x8FC60000, "USI_3")
        ida_name.set_name(0x8FD20000, "USI_4")

        ida_name.set_name(0xD0800000, "unknown_6")

        ida_name.set_name(0xC1000000, "TWOG_1")
        ida_name.set_name(0xC1001000, "TWOG_2")
        ida_name.set_name(0xC1800000, "MARCONI_1")
        ida_name.set_name(0xC2000000, "MARCONI_2")
        ida_name.set_name(0xCE000000, "unknown_7")

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
        ida_name.set_name(0xE000E000, "system control space (SCS)", 1)

        # system level
        self.add_memory_segment(0xEC000000, 0x0000FFFF, "GLINK")

        self.add_memory_segment(0xF0000000, 0x0FFFFFFF, "unknown_8")

        # 0xEACEBE8E, 0xEB86660C, 0xFF0F5D1C
        # 0x5F8A5309
        return

idb_hooks = idb_finalize_hooks_t()
idb_hooks.hook()
idc.msg("[i] Shannon postprocessor scheduled.\n")
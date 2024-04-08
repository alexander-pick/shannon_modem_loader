#!/bin/python3

# Samsung Shannon Modem Loader
# A lean IDA Pro loader for fancy baseband research 
# Alexander Pick 2024

import idaapi
import idautils
import ida_idp
import idc
import ida_auto
import ida_bytes
import ida_nalt
import ida_name

import struct

def add_data_segment(seg_start, seg_size, seg_name):

    seg_end = seg_start + seg_size

    idc.AddSeg(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes, idaapi.scPub)
    idc.set_segm_class(seg_start, "DATA")
    idc.set_segm_name(seg_start, seg_name)

def accept_file(fd, fname):
    fd.seek(0x0)
    try:
        image_type = fd.read(0x3)
    except UnicodeDecodeError:
        return 0

    if image_type == b"TOC":
        return {"format": "Shannon Baseband Image", "processor": "arm"}

    return 0

def load_file(fd, neflags, format):

    idaapi.set_processor_type("arm:ARMv7-A&R", ida_idp.SETPROC_LOADER_NON_FATAL)

    # make sure ida understands us correctly
    idc.process_config_line("ARM_DEFAULT_ARCHITECTURE = ARMv7-A&R")
    idc.process_config_line("ARM_SIMPLIFY = NO")
    idc.process_config_line("ARM_NO_ARM_THUMB_SWITCH = YES")

    # improve auto analysis
    idc.process_config_line("ARM_REGTRACK_MAX_XREFS = 0")

    if (neflags & idaapi.NEF_RELOAD) != 0:
        return 1

    start_offset = 0x20

    while(1):

        fd.seek(start_offset)
        entry = fd.read(0x20)

        #unpack TOC entry
        toc_info = struct.unpack("12sIIIII", entry)

        seg_name = str(toc_info[0], "UTF-8").strip("\x00")

        if(seg_name == ""):
            break

        seg_start = toc_info[2]
        seg_end = toc_info[2] + toc_info[3]

        # map slices to segments 
        idc.AddSeg(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes, idaapi.scPub)
        if "NV" in seg_name:
            idc.set_segm_class(seg_start, "DATA")
        else:
            idc.set_segm_class(seg_start, "CODE")
        idc.set_segm_name(seg_start, seg_name)

        fd.file2base(toc_info[1], seg_start, seg_end,  0)

        # set entry points of main and bootloader
        if seg_name == "BOOT":
            idaapi.add_entry(seg_start, seg_start, "bootloader_entry", 1)
            idc.set_cmt( seg_start, "bootloader entry point", 1)
            ida_auto.auto_make_code(seg_start)

        if seg_name == "MAIN":
            
            # b Reset_Handler
            # b . /* 0x4  Undefined Instruction */
            # b . /* 0x8  Software Interrupt */
            # b . /* 0xC  Prefetch Abort */
            # b . /* 0x10 Data Abort */
            # b . /* 0x14 Reserved */
            # b . /* 0x18 IRQ */
            # b . /* 0x1C Reserved */

            idc.set_cmt( seg_start, "vector table", 1)

            idaapi.add_entry(seg_start, seg_start, "reset", 1)

            idaapi.add_entry(seg_start+4, seg_start+4, "undef_inst", 1)

            idaapi.add_entry(seg_start+8, seg_start+8, "soft_int", 1)

            idaapi.add_entry(seg_start+12, seg_start+12, "prefetch_abort", 1)

            idaapi.add_entry(seg_start+16, seg_start+16, "data_abort", 1)

            ida_name.set_name(seg_start+20, "reserved_1", 1)
            
            idaapi.add_entry(seg_start+24, seg_start+24, "irq", 1)

            ida_name.set_name(seg_start+28, "reserved_2", 1)

            #ida_auto.auto_make_code(seg_start)

        start_offset += 0x20

    # pre-create long strings to avoid them beeing mistaken with code
    # Shannon has a lot of these and IDA ocassinly eats them

    strings = idautils.Strings()

    strings.setup(strtypes=[ida_nalt.STRTYPE_C], ignore_instructions=True, minlen=12)

    strings.refresh()

    for s in strings:
        ida_bytes.create_strlit(s.ea, 0, ida_nalt.STRTYPE_TERMCHR)

    # add additional memory ranges

    add_data_segment(0x00000000, 0xFFFF, "ITCM")
    add_data_segment(0x04800000, 0xFFFF, "unkown_boot")
    add_data_segment(0x04000000, 0x20000, "bootrom")

    add_data_segment(0x20000000, 0xFFFF, "DTCM")
    #add_data_segment(0x40000000, 0xFFFF, "AHBP")
    
    add_data_segment(0x44200000, 0x1400000, "RAM")
    add_data_segment(0x47F00000, 0x14000, "ABOX")

    add_data_segment(0x80000000, 0x10000, "unknown_1")
    add_data_segment(0x81000000, 0x2000, "unknown_2")
    add_data_segment(0x81002000, 0x10000, "unknon_3")
    add_data_segment(0x84000000, 0x10000, "UART")
    add_data_segment(0x85000000, 0x10000, "unknown_4")
    add_data_segment(0x8F900000, 0x1000, "unknown_5")
    add_data_segment(0x8FC30000, 0x1000, "USI_1")
    add_data_segment(0x8FC22000, 0x1000, "USI_2")
    add_data_segment(0x8FC60000, 0x1000, "USI_3")
    add_data_segment(0x8FD20000, 0x1000, "USI_4")

    add_data_segment(0xC1000000, 0x10000, "TWOG_1")
    add_data_segment(0xC1001000, 0x10000, "TWOG_2")
    add_data_segment(0xC1800000, 0x10000, "MARCONI_1")
    add_data_segment(0xC2000000, 0x10000, "MARCONI_2")
    
    # 0xE0000000-0xFFFFFFFF - system level use

    # 0xE0000000-0xE00FFFFF - private peripheral bus (PPB)
    add_data_segment(0xE0000000, 0x100000, "PPB")

    # 0xE000E000 to 0xE000EFFF - system control space (SCS)
    ida_name.set_name(0xE000E000, "system control space (SCS)", 1)

    add_data_segment(0xEC000000, 0x10000, "GLINK")

    return 1
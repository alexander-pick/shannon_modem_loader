#!/bin/python3

# Samsung Shannon Modem Loader
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024

import idc
import idaapi
import idautils
import ida_idp
import ida_auto
import ida_bytes
import ida_nalt
import ida_name
import ida_segment

import struct


def add_memory_segment(seg_start, seg_size, seg_name):

    seg_end = seg_start + seg_size

    idc.add_segm_ex(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes, idaapi.scPub, ida_segment.ADDSEG_SPARSE)

    idc.set_segm_class(seg_start, "DATA")
    idc.set_segm_type(seg_start, idaapi.SEG_DATA)
    idc.set_segm_name(seg_start, seg_name)
    
    #make sure it is really STT_MM (sparse) 
    ida_bytes.change_storage_type(seg_start, seg_end, 1)

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

    idaapi.set_processor_type(
        "arm:ARMv7-A&R", ida_idp.SETPROC_LOADER_NON_FATAL)

    # make sure ida understands us correctly
    idc.process_config_line("ARM_DEFAULT_ARCHITECTURE = ARMv7-A&R")
    idc.process_config_line("ARM_SIMPLIFY = NO")
    idc.process_config_line("ARM_NO_ARM_THUMB_SWITCH = YES")

    # improve auto analysis
    idc.process_config_line("ARM_REGTRACK_MAX_XREFS = 0")

    if (neflags & idaapi.NEF_RELOAD) != 0:
        return 1
    
        # add additional memory ranges

    add_memory_segment(0x00000000, 0x000FFFFF, "ITCM_low")
    add_memory_segment(0x00100000, 0x0FEFFFFF, "EXTERNAL_1")
    # add_data_segment(0x04800000, 0x0000FFFF, "unkown_boot")
    # add_data_segment(0x04000000, 0x0001FFFF, "bootrom")

    add_memory_segment(0x10000000, 0x0000FFFF, "ITCM_high")
    add_memory_segment(0x10010000, 0x0FFEFFFF, "EXTERNAL_2")

    add_memory_segment(0x20000000, 0x000FFFFF, "SRAM_DTCM")
    add_memory_segment(0x20100000, 0x1FEFFFFF, "SRAM_EXTERN") # normally 0x1FEFFFFF, but shortened as only a fraction is used

    ida_name.set_name(0x32000000, "unknown_0")

    add_memory_segment(0x40000000, 0x1EFFFFFF, "AHBP") # Pheriphials

    ida_name.set_name(0x44200000, "RAM")
    ida_name.set_name(0x47F00000, "ABOX")

    add_memory_segment(0x60000000, 0x3fffffff, "SRAM_EXTERN")

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

    add_memory_segment(0xA0000000, 0x3fffffff, "EXT_DEVICE")

    # 0xE0000000-0xFFFFFFFF - system level use

    # 0xE0000000-0xE00FFFFF - private peripheral bus (PPB)
    add_memory_segment(0xE0001000, 0x00000FFF, "PPB_DW")
    add_memory_segment(0xE0002000, 0x00000FFF, "PPB_BP")
    add_memory_segment(0xE000E000, 0x00000CFF, "PPB_NVIC")
    add_memory_segment(0xE000ED00, 0x000002FF, "PPB_DBGCTL")
    add_memory_segment(0xE0005000, 0x00000FFF, "PPB")
    add_memory_segment(0xE00FF000, 0x00000FFF, "ROM_TABLE")

    # 0xE000E000 to 0xE000EFFF - system control space (SCS)
    ida_name.set_name(0xE000E000, "system control space (SCS)", 1)

    # system level
    add_memory_segment(0xEC000000, 0x0000FFFF, "GLINK")

    start_offset = 0x20

    while (1):

        fd.seek(start_offset)
        entry = fd.read(0x20)

        # unpack TOC entry
        toc_info = struct.unpack("12sIIIII", entry)

        seg_name = str(toc_info[0], "UTF-8").strip("\x00")

        if (seg_name == ""):
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
            idc.set_cmt(seg_start, "bootloader entry point", 1)
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

            idc.set_cmt(seg_start, "vector table", 1)

            idaapi.add_entry(seg_start, seg_start, "reset", 1)

            idaapi.add_entry(seg_start+4, seg_start+4, "undef_inst", 1)

            idaapi.add_entry(seg_start+8, seg_start+8, "soft_int", 1)

            idaapi.add_entry(seg_start+12, seg_start+12, "prefetch_abort", 1)

            idaapi.add_entry(seg_start+16, seg_start+16, "data_abort", 1)

            ida_name.set_name(seg_start+20, "reserved_1", 1)

            idaapi.add_entry(seg_start+24, seg_start+24, "irq", 1)

            ida_name.set_name(seg_start+28, "reserved_2", 1)

            # ida_auto.auto_make_code(seg_start)

        start_offset += 0x20

    # pre-create long strings to avoid them beeing mistaken with code
    # Shannon has a lot of these and IDA ocassinly eats them

    strings = idautils.Strings()

    strings.setup(strtypes=[ida_nalt.STRTYPE_C],
                  ignore_instructions=True, minlen=12)

    strings.refresh()

    for s in strings:
        ida_bytes.create_strlit(s.ea, 0, ida_nalt.STRTYPE_TERMCHR)

    return 1

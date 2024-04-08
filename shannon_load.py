#!/bin/python3

#
# samsung shannon modem loader 
# API 2024
#

import idaapi
import ida_idp
import idc
import ida_auto
import struct

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
    idc.process_config_line("ARM_DEFAULT_ARCHITECTURE = metaarm")
    idc.process_config_line("ARM_SIMPLIFY = NO")
    idc.process_config_line("ARM_NO_ARM_THUMB_SWITCH = YES")

    if (neflags & idaapi.NEF_RELOAD) != 0:
        return 1

    start_offset = 0x20

    while(1):

        fd.seek(start_offset)
        entry = fd.read(0x20)

        toc_info = struct.unpack("12sIIIII", entry)

        seg_name = str(toc_info[0], "UTF-8").strip("\x00")

        if(seg_name == ""):
            break

        seg_start = toc_info[2]
        seg_end = toc_info[2] + toc_info[3]

        # AddSeg(startea, endea, base, use32, align, comb
        idc.AddSeg(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes, idaapi.scPub)
        if "NV" in seg_name:
            idc.set_segm_class(seg_start, "DATA")
        else:
            idc.set_segm_class(seg_start, "CODE")
        idc.set_segm_name(seg_start, seg_name)

        fd.file2base(toc_info[1], seg_start, seg_end,  0)

        if seg_name == "BOOT":
            idaapi.add_entry(seg_start, seg_end, "bootloader_entry", 1)
            ida_auto.auto_make_code(seg_start)

        if seg_name == "MAIN":
            idaapi.add_entry(seg_start, seg_end, "reset_vector", 1)
            ida_auto.auto_make_code(seg_start)

        start_offset += 0x20

    return 1
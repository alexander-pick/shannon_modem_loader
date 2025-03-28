#!/bin/python3

# Samsung Shannon Modem Loader
# A lean IDA Pro loader for fancy baseband research
# Alexander Pick 2024-2025

import idc
import idaapi
import idautils
import ida_idp
import ida_auto
import ida_bytes
import ida_nalt
import ida_name
import ida_expr
import ida_kernwin
import ida_segment
import ida_ida
import ida_typeinf

import struct

import shannon_structs
import shannon_generic


# This function will create DBT structs, DBT structs are debug references of various kind.
# The head contains a type byte in position 4, this indicates if a structure is a direct
# string ref or something else.
def make_dbt():
    
    sc = idautils.Strings()

    sc.setup(strtypes=[ida_nalt.STRTYPE_C],
             ignore_instructions=True, minlen=4)

    sc.refresh()

    for i in sc:
        if ("DBT:" in str(i)):

            struct_name = "dbg_trace"

            # read DBT type
            # header_type = int.from_bytes(ida_bytes.get_bytes((i.ea+3), 1), "little")
            # if(header_type != 0x3a):
            #     struct_name = "dbt"

            struct_id = idc.get_struc_id(struct_name)
            struct_size = idc.get_struc_size(struct_id)

            # make sure we start on-point
            offset = i.ea + str(i).find("DBT:")

            ida_bytes.del_items(offset, 0, struct_size)
            ida_bytes.create_struct(offset, struct_size, struct_id)

# validate if the file can be processed by the loader
def accept_file(fd, fname):

    fd.seek(0x0)

    try:
        image_type = fd.read(0x3)
    except UnicodeDecodeError:
        return 0

    if (image_type == b"TOC"):
        return {"format": "Shannon Baseband Image", "processor": "arm"}

    return 0

# required IDA Pro load file function
def load_file(fd, neflags, format):

    version_string = None

    # Old Exynos are ARMv7 (Exynos 3/4/5), old Shannon was Cortex R7, newer are R8.
    # New Exynos are all ARMv8+, but Shannon seems to be still running on a A or R core with ARMv7 ISA.
    # Tensor's Modem seems to be ARMv8 or it does weird things occassionaly

    idaapi.set_processor_type("arm:ARMv7-A&R", ida_idp.SETPROC_LOADER_NON_FATAL)
    idc.process_config_line("ARM_DEFAULT_ARCHITECTURE = ARMv7-A&R")

    idc.process_config_line("ARM_SIMPLIFY = NO")
    idc.process_config_line("ARM_NO_ARM_THUMB_SWITCH = NO")

    # improve auto analysis
    idc.process_config_line("ARM_REGTRACK_MAX_XREFS = 0")

    # disable Coagulate and colapse
    idc.process_config_line("ANALYSIS = 0x9bff9ff7ULL")

    # set compiler defaults
    idc.set_inf_attr(idc.INF_COMPILER, idc.COMP_GNU)

    # call convention
    # https://hex-rays.com/products/ida/support/idadoc/285.shtml
    idc.set_inf_attr(idc.INF_MODEL, idaapi.CM_N32_F48 | idaapi.CM_M_NN | idaapi.CM_CC_FASTCALL)

    # datatype sizes
    # https://developer.arm.com/documentation/dui0282/b/arm-compiler-reference/c-and-c---implementation-details/basic-data-types?lang=en

    idc.set_inf_attr(idc.INF_SIZEOF_BOOL, 1)
    idc.set_inf_attr(idc.INF_SIZEOF_SHORT, 2)
    idc.set_inf_attr(idc.INF_SIZEOF_INT, 4)
    idc.set_inf_attr(idc.INF_SIZEOF_ENUM, 4)
    idc.set_inf_attr(idc.INF_SIZEOF_LONG, 4)
    idc.set_inf_attr(idc.INF_SIZEOF_LLONG, 8)
    idc.set_inf_attr(idc.INF_SIZEOF_LDBL, 8)

    # set type library ARM C v1.2
    idc.add_default_til("armv12")

    # Set predefined macros for the target compiler
    ida_typeinf.set_c_macros(ida_idp.cfg_get_cc_predefined_macros(idc.COMP_GNU))

    # Get the include directory path of the target compiler
    ida_typeinf.set_c_header_path(ida_idp.cfg_get_cc_header_path(idc.COMP_GNU))

    ida_typeinf.set_c_header_path(ida_idp.cfg_get_cc_header_path(idc.COMP_GNU))

    # demangle names
    idc.process_config_line("DemangleNames = 1")
    # check the gcc 3.x name box if not set
    ida_ida.inf_set_demnames(ida_ida.inf_get_demnames() | idaapi.DEMNAM_GCC3)

    if (neflags & idaapi.NEF_RELOAD != 0):
        return 1

    # make sure the idb is seen as 32 bit even if opened in ida64
    idaapi.inf_set_app_bitness(32)

    # force disble autoanalysis for avoid crashes
    if ida_auto.is_auto_enabled():
        ida_auto.auto_wait()


    # this is needed to clear the output window
    output = ida_kernwin.find_widget("Output window")
    ida_kernwin.activate_widget(output, True)
    idaapi.process_ui_action("msglist:Clear")

    idc.msg("\nIDA Pro and Home 8.x+/9.x\n")
    idc.msg(r'      /\ \                                                    ' + "\n")
    idc.msg(r'   ___\ \ \___      __       __      __     ___      __       ' + "\n")
    idc.msg(r'  /`,__| \  _ `\  /`__`\   /` _`\  /` _`\  / __`\  /` _`\     ' + "\n")
    idc.msg(r' /\__, `\ \ \ \ \/\ \_\.\_/\ \/\ \/\ \/\ \/\ \_\ \/\ \/\ \    ' + "\n")
    idc.msg(r' \/\____/\ \_\ \_\ \__/.\_\ \_\ \_\ \_\ \_\ \____/\ \_\ \_\   ' + "\n")
    idc.msg(r'  \/___/  \/_/\/_/\/__/\/_/\/_/\/_/\/_/\/_/\/___/  \/_/\/_/   ' + "\n")
    idc.msg(r'                                               Modem Loader   ' + "\n\n")
    idc.msg("More: https://github.com/alexander-pick/shannon_modem_loader\n\n")

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

        # these seem to be present mostly in older images
        if (seg_name == "OFFSET" and seg_start == 0x0):
            
            idc.msg("[i] found OFFSET, skipping\n")
            start_offset += 0x20
            continue

        if (seg_name == "GVERSION" and seg_start == 0x0):

            idc.msg("[i] found GVERSION, this is Tensor land\n")

            idaapi.set_processor_type("arm:ARMv8", ida_idp.SETPROC_LOADER_NON_FATAL)
            idc.process_config_line("ARM_DEFAULT_ARCHITECTURE = ARMv8")

            # limit for performance reasons
            #idc.process_config_line("ARM_REGTRACK_MAX_XREFS = 512")

            tensor = True
            start_offset += 0x20

            continue

        # map slices to segments
        idc.msg("[i] adding %s\n" % seg_name)
        idc.AddSeg(seg_start, seg_end, 0, 1, idaapi.saRel32Bytes, idaapi.scPub)

        if ("NV" in seg_name):
            idc.set_segm_class(seg_start, "DATA")
        else:
            idc.set_segm_class(seg_start, "CODE")

        idc.set_segm_name(seg_start, seg_name + "_file")

        fd.file2base(toc_info[1], seg_start, seg_end, 0)

        # set entry points of main and bootloader
        if (seg_name == "BOOT"):

            #mark RX
            idc.set_segm_attr(seg_start, idc.SEGATTR_PERM, ida_segment.SEGPERM_EXEC |
                              ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

            idaapi.add_entry(seg_start, seg_start, "bootloader_entry", 1)
            idc.set_cmt(seg_start, "bootloader entry point", 1)
            ida_auto.auto_make_code(seg_start)

        # process main segment and create vector table
        if (seg_name == "MAIN"):

            # mark RX
            idc.set_segm_attr(seg_start, idc.SEGATTR_PERM, ida_segment.SEGPERM_EXEC |
                              ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

            # the fancy "ShannonOS" string,
            version_addr = shannon_generic.search_text(seg_start, seg_end, "_ShannonOS_")
            if (version_addr != None):
                version_string = idc.get_strlit_contents(version_addr)

            # 0x0  Reset
            # 0x4  Undefined Instruction
            # 0x8  Software Interrupt
            # 0xC  Prefetch Abort
            # 0x10 Data Abort
            # 0x14 Reserved
            # 0x18 IRQ
            # 0x1C Reserved

            ida_auto.auto_make_code(seg_start)

            idc.set_cmt(seg_start, "vector table", 1)

            idaapi.add_entry(seg_start, seg_start, "reset", 1)

            idaapi.add_entry(seg_start + 4, seg_start + 4, "undef_inst", 1)

            idaapi.add_entry(seg_start + 8, seg_start + 8, "soft_int", 1)

            idaapi.add_entry(seg_start + 12, seg_start + 12, "prefetch_abort", 1)

            idaapi.add_entry(seg_start + 16, seg_start + 16, "data_abort", 1)

            ida_name.set_name(seg_start + 20, "reserved_1", ida_name.SN_NOCHECK)

            idaapi.add_entry(seg_start + 24, seg_start + 24, "irq", 1)

            idaapi.add_entry(seg_start + 28, seg_start + 28, "fiq", 1)

        if (seg_name == "VSS"):
            # mark RX
            idc.set_segm_attr(seg_start, idc.SEGATTR_PERM, ida_segment.SEGPERM_EXEC |
                              ida_segment.SEGPERM_READ | ida_segment.SEGPERM_WRITE)

        start_offset += 0x20

    idc.msg("[i] Loader completed successfully.\n")

    # let's do that before creating any code (avoids false positives in AA)
    shannon_generic.create_long_strings()

    # needs to be done very early
    shannon_structs.add_dbt_struct()
    make_dbt()

    shannon_structs.add_scatter_struct()
    shannon_structs.add_mpu_region_struct()
    shannon_structs.add_task_struct()

    # These 3 lines were awarded the most ugliest hack award 2024, runs a script which scheudles a callback without
    # beeing unloaded with the loader.

    rv = ida_expr.idc_value_t()
    idc_line = 'RunPythonStatement("exec(open(\'' + idaapi.idadir(
        "python") + '/shannon_postprocess.py\').read())")'
    ida_expr.eval_idc_expr(rv, idaapi.BADADDR, idc_line)

    if (version_string != None):
        idc.msg("[i] RTOS version:%s\n" % version_string.decode().replace("_", " "))

    idc.msg("[i] loader done, starting auto analysis\n")

    return 1

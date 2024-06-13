#!/bin/python3

# Samsung Shannon Modem Loader - Postprocessor
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024

import idc
import idaapi
import idautils
import ida_idp
import ida_name
import ida_idp
import ida_segment
import ida_name
import ida_strlist
import ida_ua
import ida_funcs
import ida_nalt
import ida_auto

import time

import shannon_pal_reconstructor
import shannon_generic
import shannon_mpu
import shannon_scatterload
import shannon_debug_traces
import shannon_names

# identify the non returning function which belongs to the stack protection, if it exists
# we deal with a very new BB - like 5G new.
def find_cookie_monster():
    
    seg_t = ida_segment.get_segm_by_name("MAIN_file")
    
    offset = shannon_generic.search_text(seg_t.start_ea, seg_t.end_ea, "Check a function")
    offset = shannon_generic.get_first_ref(offset)
    
    if(offset != None):
        
        idc.msg("[i] found stack protection handler at %x\n" % offset)
        
        cookie_func_start = idc.get_func_attr(offset, idc.FUNCATTR_START)
        
        ida_name.set_name(cookie_func_start, "stack_err", ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        
        return True
    
    return False

class idb_finalize_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    # ida's standard post processing callback
    def auto_empty_finally(self):

        # start calculating runtime
        start_time = time.process_time()

        # show a "please wait .." box
        idaapi.show_wait_box(
            'HIDECANCEL\nPost-processing modem image, please wait...')

        # from here on do the fancy stuff

        shannon_debug_traces.make_dbt_refs()
        
        find_cookie_monster()
        
        shannon_pal_reconstructor.find_basic_pal_functions()

        shannon_names.restore_ss_names()
        shannon_names.restore_cpp_names()
        shannon_generic.create_long_strings()

        for s in idautils.Segments():

            seg_start = idc.get_segm_start(s)
            seg_name = idc.get_segm_name(seg_start)

            # add some names
            if (seg_name == "BOOT_file"):

                shannon_generic.get_ref_set_name(seg_start, "start")

            if (seg_name == "MAIN_file"):

                shannon_generic.get_ref_set_name(seg_start, "reset_v")

                shannon_generic.get_ref_set_name(seg_start + 4, "undef_inst_v")

                shannon_generic.get_ref_set_name(seg_start + 8, "soft_int_v")

                shannon_generic.get_ref_set_name(seg_start + 12, "prefetch_abort_v")

                shannon_generic.get_ref_set_name(seg_start + 16, "data_abort_v")
                
                shannon_generic.get_ref_set_name(seg_start + 20, "reserved_v")

                shannon_generic.get_ref_set_name(seg_start + 24, "irq_v")
                
                shannon_generic.get_ref_set_name(seg_start + 28, "fiq_v")

                self.memory_ranges()
                
                # it is very important to do this in the correct order
                # especially for new modems or the result will be left 
                # in a weird state

                shannon_mpu.find_hw_init()

                shannon_scatterload.find_scatter()

        # remove "please wait ..." box and display runtime in log
        idaapi.hide_wait_box()

        for s in idautils.Segments():

            # reschedule everything for a last auto analysis pass
            idc.plan_and_wait(idc.get_segm_start(s), idc.get_segm_end(s))

        # fix strings a last time
        idautils.Strings().setup(strtypes=[ida_nalt.STRTYPE_C], ignore_instructions=True, minlen=6)
        ida_strlist.build_strlist()
        
        timediff = time.process_time() - start_time
        idc.msg("[i] post-processing runtime %d minutes and %d seconds\n" %
                ((timediff / 60), (timediff % 60)))

        return

    # this adds some memory ranges which are defined in the ARMv7 spec, it also names some "known" offsets
    # LSI does not follow the spec very closly but this is better than nothing and helps to with the auto analysis

    def memory_ranges(self):
        # add additional memory ranges

        #shannon_generic.add_memory_segment(0x00000000, 0x000FFFFF, "ITCM_low")
        shannon_generic.add_memory_segment(0x00100000, 0x0FEFFFFF, "EXTERNAL_1")
        # add_data_segment(0x04800000, 0x0000FFFF, "unkown_boot")
        # add_data_segment(0x04000000, 0x0001FFFF, "bootrom")

        #shannon_generic.add_memory_segment(0x10000000, 0x0000FFFF, "ITCM_high")
        #shannon_generic.add_memory_segment(0x10010000, 0x0FFEFFFF, "EXTERNAL_2")

        shannon_generic.add_memory_segment(0x20000000, 0x000FFFFF, "SRAM_DTCM")
        shannon_generic.add_memory_segment(0x20100000, 0x1FEFFFFF, "SRAM_EXTERN")

        ida_name.set_name(0x32000000, "unknown_0", ida_name.SN_NOCHECK)

        # Normaly Pheriphials but this is used differently
        #shannon_generic.add_memory_segment(0x40000000, 0x1EFFFFFF, "AHBP")

        ida_name.set_name(0x44200000, "RAM", ida_name.SN_NOCHECK)
        ida_name.set_name(0x47F00000, "ABOX", ida_name.SN_NOCHECK)

        shannon_generic.add_memory_segment(0x60000000, 0x3fffffff, "SRAM_EXTERN")

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

        #shannon_generic.add_memory_segment(0xA0000000, 0x3fffffff, "EXT_DEVICE")

        # 0xE0000000-0xFFFFFFFF - system level use
        #shannon_generic.add_memory_segment(0xE0000000, 0x1FFFFFFF, "SYSTEM")

        # 0xE0000000-0xE00FFFFF - private peripheral bus (PPB)
        #shannon_generic.add_memory_segment(0xE0000000, 0x000FFFFF, "PPB")

        shannon_generic.add_memory_segment(0xE0001000, 0x00000FFF, "PPB_DW")
        shannon_generic.add_memory_segment(0xE0002000, 0x00000FFF, "PPB_BP")
        shannon_generic.add_memory_segment(0xE000E000, 0x00000CFF, "PPB_NVIC")
        shannon_generic.add_memory_segment(0xE000ED00, 0x000002FF, "PPB_DBGCTL")
        shannon_generic.add_memory_segment(0xE0005000, 0x00000FFF, "PPB")
        shannon_generic.add_memory_segment(0xE00FF000, 0x00000FFF, "ROM_TABLE")

        # 0xE000E000 to 0xE000EFFF - system control space (SCS)
        ida_name.set_name(
            0xE000E000, "system control space (SCS)", ida_name.SN_NOCHECK)

        # system level
        shannon_generic.add_memory_segment(0xEC000000, 0x0000FFFF, "GLINK")

        #shannon_generic.add_memory_segment(0xF0000000, 0x0FFFFFFF, "unknown_8")


idb_hooks = idb_finalize_hooks_t()
idb_hooks.hook()
idc.msg("[i] Shannon postprocessor scheduled.\n")

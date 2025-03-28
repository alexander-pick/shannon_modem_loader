#!/bin/python3

# Samsung Shannon Modem Loader - Postprocessor
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024-2025

import idc
import idaapi
import idautils
import ida_idp
import ida_name
import ida_idp
import ida_segment
import ida_name
import ida_strlist
import ida_nalt
import ida_kernwin
import ida_typeinf
import ida_ua
import ida_funcs

import time
import os
import pwd
import glob
import threading
import time

import shannon_pal_reconstructor
import shannon_generic
import shannon_mpu
import shannon_scatterload
import shannon_debug_traces
import shannon_names
import shannon_indirect_xref

post_processed = False

# identify the non returning function which belongs to the stack protection, if it exists
# we deal with a very new BB - like 5G new.
def find_cookie_monster():

    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    offset = shannon_generic.search_text(seg_t.start_ea, seg_t.end_ea, "Check a function")
    offset = shannon_generic.get_first_ref(offset)

    if (offset != None and offset != idaapi.BADADDR):

        idc.msg("[i] found stack protection handler at %x\n" % offset)

        cookie_func_start = idc.get_func_attr(offset, idc.FUNCATTR_START)

        ida_name.set_name(cookie_func_start, "stack_err", ida_name.SN_NOCHECK | ida_name.SN_FORCE)

        return True

    return False

def find_rvct():

    ARM_reference_compiler = "ARM_Compiler_"

    seg_t = ida_segment.get_segm_by_name("MAIN_file")

    rvct_addr_str = shannon_generic.search_text(seg_t.start_ea, seg_t.end_ea, "ARM RVCT")

    if (rvct_addr_str != None):

        #find start of the string for xref
        rvct_addr_str = idc.get_item_head(rvct_addr_str)

        rvct_major_ver = ""
        rvct_minor_ver = ""
        rvct_build = ""

        for rvct_xref in idautils.XrefsTo(rvct_addr_str, 0):
            # ARM RVCT %d.%d [Build %d]
            prev_head = idc.prev_head(rvct_xref.frm)

            opcode = ida_ua.ua_mnem(prev_head)

            if (opcode == None):
                continue

            # in case there is a split string ref etc.
            if (not "MOV" in opcode):
                continue

            rvct_major_ver = idc.get_operand_value(prev_head, 1)

            prev_head = idc.prev_head(prev_head)
            rvct_minor_ver = idc.get_operand_value(prev_head, 1)

            prev_head = idc.prev_head(prev_head)
            rvct_build = idc.get_operand_value(prev_head, 1)
            
            # old images have switched build and subversion
            if(rvct_minor_ver > rvct_build):
                tmp = rvct_minor_ver
                rvct_minor_ver = rvct_build
                rvct_build = tmp

            idc.msg("[i] build using ARM RVCT %d.%02d [Build %d]\n" %
                    (rvct_major_ver, rvct_minor_ver, rvct_build))

            # there is commonly just one ref
            break

        if (rvct_major_ver):
            home_dir = os.path.expanduser(f"~{pwd.getpwuid(os.geteuid())[0]}/")

            # find matching RVCT installs and set them as include path, if multiple are found -> ask

            rvct_paths = glob.glob(
                home_dir + "/" + ARM_reference_compiler + "*" + str(rvct_build))

            for rvct in rvct_paths:

                header_path = rvct + "/include/"

                if (len(rvct_paths) > 1):
                    ARM_inc_dir = ida_kernwin.ask_yn(
                        1, "HIDECANCEL\nUse " + header_path + " as include path?")
                else:
                    ARM_inc_dir = True

                if (ARM_inc_dir):
                    if (os.path.isdir(header_path)):
                        ida_typeinf.set_c_header_path(header_path)
                        idc.msg("[i] set c_header_path to %s\n" % header_path)

                    break

            # apply signatures if present
            for sigdir in idaapi.get_ida_subdirs("sig"):

                rvct_sig_file = ARM_reference_compiler + "*" + str(rvct_build) + ".sig"
                sig_glob = sigdir + "/arm/" + rvct_sig_file
                sig_files = glob.glob(sig_glob)

                for sig_file in sig_files:

                    if (os.path.exists(sig_file)):
                        
                        idc.msg("[i] applying signature file %s to all functions in database\n" % sig_file)

                        func_cnt = 0
                        
                        for function_ea in idautils.Functions():
                            #check that the function has no name yet
                            if("sub_" in ida_funcs.get_func_name(function_ea)):
                                #shannon_generic.DEBUG("[d] %x\n" % function_ea)
                                func_cnt += 1
                                idaapi.apply_idasgn_to(sig_file, function_ea, 0)
                        
                        idc.msg("[i] checked %d functions for signature matches\n" % func_cnt)
                        
                    else:

                        idc.msg("[i] cannot find signature file %s, please create one\n" %
                                sig_file)

class idb_finalize_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)

    # ida's standard post processing callback
    def auto_empty_finally(self):
        
        global post_processed
        
        # avoid this to be triggered twice
        if(post_processed is True): 
            return
        else:
            post_processed = True
        
        # avoid multiple execution paths if a segment get split due to scatter etc.
        boot_processed_once = False
        main_processed_once = False

        # start calculating runtime
        start_time = time.process_time()

        # from here on do the fancy stuff

        shannon_debug_traces.make_dbt_refs()

        shannon_names.restore_ss_names()
        shannon_names.restore_cpp_names()
        shannon_generic.create_long_strings()

        if(find_cookie_monster()):
            # this is a thing for newer baseband versions
            shannon_indirect_xref.scan_main_indirect_refs()

        for s in idautils.Segments():

            seg_start = idc.get_segm_start(s)
            seg_name = idc.get_segm_name(seg_start)

            # add some names
            if (seg_name == "BOOT_file"):
    
                if(boot_processed_once is False):
                    
                    boot_processed_once = True

                    shannon_generic.get_ref_set_name(seg_start, "start")

            if (seg_name == "MAIN_file"):
                
                if(main_processed_once is False):
                    
                    main_processed_once = True

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
                    shannon_mpu.scan_for_mrc()

                    shannon_scatterload.find_scatter()

                    shannon_pal_reconstructor.find_pal_msg_funcs()
                    shannon_pal_reconstructor.find_pal_init()

        find_rvct()

        # remove "please wait ..." box and display runtime in log
        idaapi.hide_wait_box()

        for s in idautils.Segments():

            # reschedule everything for a last auto analysis pass
            idc.plan_and_wait(idc.get_segm_start(s), idc.get_segm_end(s))

        # fix strings a last time
        idautils.Strings().setup(strtypes=[ida_nalt.STRTYPE_C],
                                 ignore_instructions=True, minlen=6)
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

## ADDED BY ENOKSETH FOR AVOIDING WAIT BOXES AND CRASH 

# Affiche la fenêtre "please wait..." uniquement si le mode debug n'est pas activé
if not shannon_generic.is_debug:
    idaapi.show_wait_box('HIDECANCEL\nPost-processing modem image, please wait...')

# Cette fonction essaie de cacher la wait box en toute sécurité
def safe_hide_wait_box():
    try:
        idaapi.hide_wait_box()
        idc.msg("[✓] Wait box closed successfully.\n")
    except Exception as e:
        idc.msg(f"[!] Error closing wait box: {e}\n")

# Hook secondaire au cas où le post-processing ne la ferme pas
class WaitBoxManager(ida_idp.IDB_Hooks):
    def auto_empty_finally(self):
        if not shannon_generic.is_debug:
            safe_hide_wait_box()

# Remplace les deux hooks par un seul
waitbox_hook = WaitBoxManager()
waitbox_hook.hook()


# Optionnel : ajoute une sécurité supplémentaire avec timeout automatique

def force_hide_after_timeout(timeout=120):
    time.sleep(timeout)
    idc.msg("[!] Timeout reached, forcing wait box close.\n")
    safe_hide_wait_box()

threading.Thread(target=force_hide_after_timeout, daemon=True).start()

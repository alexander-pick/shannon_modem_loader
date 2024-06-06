#!/bin/python3

# Samsung Shannon Modem Loader - Tensor Postprocessor
# This script is autoamtically scheduled by the loader
# Alexander Pick 2024

import idc
import idaapi
import idautils
import ida_idp
import ida_idp
# import ida_name

import time

import shannon_generic
import shannon_debug_traces

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

        # remove "please wait ..." box and display runtime in log
        idaapi.hide_wait_box()

        timediff = time.process_time() - start_time
        idc.msg("[i] post-processing runtime %d minutes and %d seconds\n" %
                ((timediff / 60), (timediff % 60)))

        for s in idautils.Segments():

            # reschedule everything for a last auto analysis pass
            idc.plan_and_wait(idc.get_segm_start(s), idc.get_segm_end(s))

        return

    def memory_ranges(self):
        # add additional memory ranges
        return

idb_hooks = idb_finalize_hooks_t()
idb_hooks.hook()
idc.msg("[i] Tensor postprocessor scheduled.\n")

# Samsung Shannon Modem Loader - WIP
# Alexander Pick 2024

# script to find the count of xrefs to a segment
# I use this to debug/check the memory map, runs a while so be patient

import idautils
import idc

for s in idautils.Segments():

    count = 0 

    seg_start = idc.get_segm_start(s)
    seg_end = idc.get_segm_end(s)
    seg_cur = seg_start

    while seg_cur <= seg_end:
        for xref in idautils.XrefsTo(seg_cur,  0):
            count += 1
        seg_cur += 1

    print("%s: %x-%x has %d xrefs" % (str(s), seg_start, seg_end, count))    
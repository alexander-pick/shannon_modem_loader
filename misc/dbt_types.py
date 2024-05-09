# Samsung Shannon Modem Loader - WIP
# Alexander Pick 2024

# scripts to extract DBT struct types for analysis purpose

import ida_bytes
import idautils
import ida_struct

struct_id = ida_struct.get_struc_id("dbt_struct")
all_structs = idautils.XrefsTo(struct_id, 0)

for i in all_structs:

    sptr = ida_struct.get_struc(struct_id)
                
    head_ptr = ida_struct.get_member_by_name(sptr, "head")
    header = int.from_bytes(ida_bytes.get_bytes(i.frm+head_ptr.soff, 4), "little")
    header_type = int.from_bytes(ida_bytes.get_bytes(i.frm+head_ptr.soff+3, 1), "little")
    print("%x: %x" % (i.frm,header_type))
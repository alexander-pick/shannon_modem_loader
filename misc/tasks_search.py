# Samsung Shannon Modem Loader - WIP
# Alexander Pick 2024

# task identifier, work in progress

import ida_bytes
import idautils
import ida_struct
import idc

def add_task_struct():
    #Task Structure
    struct_id = idc.add_struc(0, "task_struct", 0)
    idc.add_struc_member(struct_id, "unknown_0", -1, idaapi.FF_DWORD, -1, 4) 
    idc.add_struc_member(struct_id, "unknown_1", -1, idaapi.FF_DWORD, -1, 4) 
    idc.add_struc_member(struct_id, "unknown_2", -1, idaapi.FF_DWORD, -1, 4) 
    idc.add_struc_member(struct_id, "unknown_3", -1, idaapi.FF_DWORD, -1, 4) 
    idc.add_struc_member(struct_id, "unknown_4", -1, idaapi.FF_DWORD, -1, 4)
    idc.add_struc_member(struct_id, "task_name", -1, idaapi.FF_DWORD, -1, 4) 
    idc.add_struc_member(struct_id, "unknown_5", -1, idaapi.FF_DWORD, -1, 4)
    idc.add_struc_member(struct_id, "unknown_6", -1, idaapi.FF_DWORD, -1, 4)
    idc.add_struc_member(struct_id, "task_ptr", -1, idaapi.FF_DWORD, -1, 4) 

# struct task_struct
# {
#   int unknown_0; <- first value
#   int unknown_1;
#   int unknown_2;
#   int unknown_3;
#   int unknown_4;
#   char *task_name; <- interesting
#   int unknown_5;
#   int unknown_6;
#   char *task_ptr;
# }; + 540 padding

add_task_struct()

sc = idautils.Strings()

for i in sc:
    if(str(i) == "MSD_OT"):

        for xref in idautils.DataRefsTo(i.ea):

            ea = xref
            
            while 1:
                print(hex(ea))
                struct_id = ida_struct.get_struc_id("task_struct")
                struct_size = ida_struct.get_struc_size(struct_id)
                ida_bytes.del_items(ea, 0,  struct_size)
                ida_bytes.create_struct(ea, struct_size, struct_id)

                ea += 540

                if(int.from_bytes(ida_bytes.get_bytes(ea, 4), "little")):
                    break
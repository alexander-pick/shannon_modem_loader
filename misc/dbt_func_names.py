# Samsung Shannon Modem Loader - WIP
# Alexander Pick 2024

# rename functions based on debug strings, this is a bit fuzzy but better than nothing
# because of the mixed results I decided to keep this as an external script

# use scripts load to run this

import ida_bytes
import idautils
import ida_struct
import idc
import idaapi
import ida_funcs

import re

struct_id = ida_struct.get_struc_id("dbt_struct")
all_structs = idautils.XrefsTo(struct_id, 0)

for i in all_structs:

    sptr = ida_struct.get_struc(struct_id)
                
    str_ptr = ida_struct.get_member_by_name(sptr, "msg_ptr")
    str_offset = int.from_bytes(ida_bytes.get_bytes(i.frm+str_ptr.soff, 4), "little")
    msg_str = idc.get_strlit_contents(str_offset)

    if(msg_str != None):
        prefix = re.search("\[([a-zA-Z]+)\]", msg_str.decode())
        func_name = re.search("\] ([a-zA-Z\ ]+)", msg_str.decode())

        if(prefix != None and func_name != None):
            prefix = prefix.group()
            func_name = func_name.group().rstrip()
            prefix = prefix.replace("[","")
            prefix = prefix.replace("]", "")
            func_name = func_name.replace("]","")
            func_name = func_name.replace(" ","_")
            
            for xref_dbt in idautils.XrefsTo(i.frm,  0):

                func_start = idc.get_func_attr(xref_dbt.frm, idc.FUNCATTR_START)

                if(func_start !=  idaapi.BADADDR):
                    print("%s %s%s" % (hex(func_start), prefix, func_name))
                    # just set the first possible name found
                    if("sub_" in ida_funcs.get_func_name(func_start)):
                        try:
                            idaapi.set_name(func_start, prefix+func_name)
                        except:
                            pass
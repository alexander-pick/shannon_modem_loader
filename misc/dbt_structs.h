/*

    Samsung Shannon Modem Loader - WIP
    Alexander Pick 2024

    This just documents the DBTrace structs a bit

    Debug Trace Type Structs:

    3a - string and file ref
    40 - unknown - seems to have one  more field
    42 - unknown - seems to have one  more field
    44 - unknown - seems to have one  more field
    54 - unknown

*/

struct {
    char magic[3];              // DBT
    char struct_type;           // trace type
    unsigned int group;         // trace group
    unsigned int channel;       // trace channel
    unsigned int unknown_1; 
    unsigned int unknown_2;
    unsigned int unknown_3;
} dbt_base;

// 3a - string and file ref
struct {
    char magic[3];              // DBT
    char struct_type;           // trace type
    unsigned int group;         // trace group
    unsigned int channel;       // trace channel
    unsigned int num_param;     // number of formatstring params
    char* msg_ptr;              // ptr to formatstring
    unsigned int line;          // line number
    unsigned int file_name;     // file name
} dbt_struct;


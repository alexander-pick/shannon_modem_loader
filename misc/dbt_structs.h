/*

    Samsung Shannon Modem Loader - WIP
    Alexander Pick 2024

    This just documents the DBT structs a bit

    DBT Type Structs:

    3a - string and file ref
    40 - unknown - seems to have one  more field
    42 - unknown - seems to have one  more field
    44 - unknown - seems to have one  more field
    54
*/

struct {
    char magic[3];          // DBT
    char struct_type;
    unsigned int id;
    unsigned int type;
    unsigned int unknown_1; 
    unsigned int unknown_2;
    unsigned int unknown_3;
} dbt_base;

// 3a - string and file ref
struct {
    char magic[3];          // DBT
    char struct_type;
    unsigned int id;
    unsigned int type;
    unsigned int num_param; // number of format string params
    char* msg_ptr;          // ptr to msg
    unsigned int line;      // line number
    unsigned int file;      // file name
} dbt_struct;


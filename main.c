#include "ElfParser.h"
#include <string.h>
int main(int argc ,char **argv)
{
    ParsedElf *p = parse("./prog", "check_password");
    printf("entry: %lu \n", p->header->e_entry);
    printf(".text section offset %lu \n", p->text_header->sh_offset);
    printf(".symtab section offset %lu \n", p->symtab_header->sh_offset);
    printf(".strtab section offset %lu \n", p->string_header->sh_offset);
    printf("func address is : %p\n", p->br_address);

    return 0;
}

// gcc -std=c99 main.c ElfParser.c
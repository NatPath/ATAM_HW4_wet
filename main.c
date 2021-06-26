#include "ElfParser.h"
#include <string.h>
int main()
{
    ParsedElf *p = parse("./prog", "_start");
    printf("entry: %lu \n", p->header->e_entry);
    printf(".text section offset %lu \n", p->text_header->sh_offset);
    printf(".symtab section offset %lu \n", p->symtab_header->sh_offset);
    printf(".strtab section offset %lu \n", p->string_header->sh_offset);

    return 0;
}

// gcc -std=c99 main.c ElfParser.c
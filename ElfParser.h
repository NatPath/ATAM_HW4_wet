#include <stdio.h>
#include "elf64.h"

typedef struct
{
    Elf64_Ehdr *header;
    Elf64_Shdr *text_header;
    Elf64_Shdr *symtab_header;
    Elf64_Sym *target_func;
    long ret_address;
} ParsedElf;

ParsedElf *parse(const char *path_to_elf, const char *target_func_name);
void parse_elf_header(ParsedElf *parsedElf, const char *path_to_elf);
void parse_text_header(ParsedElf *parsedElf, const char *path_to_elf);
void parse_symbol_entry(ParsedElf *parsedElf, const char *path_to_elf, const char *target_func_name);
void destroy(ParsedElf *parsedElf);

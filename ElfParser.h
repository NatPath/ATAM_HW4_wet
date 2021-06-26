#ifndef _ELFPARSER_H
#define _ELFPARSER_H
#include <stdio.h>
#include "elf64.h"

typedef struct
{
    Elf64_Ehdr *header;
    Elf64_Shdr *text_header;
    Elf64_Shdr *string_header;
    Elf64_Shdr *symtab_header;
    Elf64_Sym *target_func;
    long ret_address;
} ParsedElf;

ParsedElf *parse(const char *path_to_elf, const char *target_func_name);
void parse_elf_header(ParsedElf *parsedElf, const char *path_to_elf);
void parse_section_headers(ParsedElf *parsedElf, const char *path_to_elf);
void parse_symbol_entry(ParsedElf *parsedElf, const char *path_to_elf, const char *target_func_name);
char* get_section_name(ParsedElf *parsed, const char *path_to_elf, Elf64_Shdr *section);
char* get_symbol_name(ParsedElf *parsed, const char *path_to_elf, Elf64_Sym *symbol);
void destroy(ParsedElf *parsedElf);

#endif

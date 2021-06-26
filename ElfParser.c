#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf64.h"
#include "ElfParser.h"

ParsedElf *parse(const char *path_to_elf, const char *target_func_name)
{
    ParsedElf *parsed = malloc(sizeof(ParsedElf));
    parse_elf_header(parsed, path_to_elf);
    parse_text_header(parsed, path_to_elf);
    //parse_symbol_entry(parsedElf, path_to_elf, target_func_name);
    return parsed;
}

void parse_elf_header(ParsedElf *parsedElf, const char *path_to_elf)
{
    Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
    FILE *file = fopen(path_to_elf, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed opening the following file : '%s'\n", path_to_elf);
        return;
    }
    int read_res = fread(header, sizeof(Elf64_Ehdr), 1, file);
    if (read_res == 0)
    {
        fprintf(stderr, "Failed reading the header of the following file : '%s'\n", path_to_elf);
        return;
    }
    (*parsedElf).header = header;
}

void parse_text_header(ParsedElf *parsedElf, const char *path_to_elf)
{
    int i = 0;
    Elf64_Shdr *text_header = malloc(sizeof(Elf64_Shdr));
    FILE *file = fopen(path_to_elf, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed opening the following file : '%s'\n", path_to_elf);
        return;
    }
    fseek(file, (*parsedElf).header->e_shoff, SEEK_SET);
    do
    {
        int read_res = fread(text_header, sizeof(Elf64_Ehdr), 1, file);
        if (read_res == 0)
        {
            fprintf(stderr, "Failed reading the header of the following file : '%s'\n", path_to_elf);
            return;
        }
        i++;
    } while (!strcmp(text_header->sh_name, ".text") && i < parsedElf->header->e_shnum);

    Elf64_Shdr *symtab_header = malloc(sizeof(Elf64_Shdr));
    fseek(file, (*parsedElf).header->e_shoff, SEEK_SET);
    i = 0;
    do
    {
        int read_res = fread(symtab_header, sizeof(Elf64_Ehdr), 1, file);
        if (read_res == 0)
        {
            fprintf(stderr, "Failed reading the header of the following file : '%s'\n", path_to_elf);
            return;
        }
        i++;
    } while (!strcmp(symtab_header->sh_name, ".symtab") && i < parsedElf->header->e_shnum);

    (*parsedElf).text_header = text_header;
    (*parsedElf).symtab_header = symtab_header;
}

void parse_symbol_entry(ParsedElf *parsedElf, const char *path_to_elf, const char *target_func_name)
{
    FILE *file = fopen(path_to_elf, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed opening the following file : '%s'\n", path_to_elf);
        return;
    }

    Elf64_Sym *symbol = malloc(sizeof(Elf64_Sym));
    fseek(file, (*parsedElf).header->e_shoff, SEEK_SET);
    do
    {
        int read_res = fread(symbol, sizeof(Elf64_Sym), 1, file);
        if (read_res == 0)
        {
            fprintf(stderr, "Failed reading the header of the following file : '%s'\n", path_to_elf);
            return;
        }
    } while (!strcmp(symbol->st_name, target_func_name));

    (*parsedElf).target_func = symbol;
    ;
}

void destroy(ParsedElf *parsed)
{
    free(parsed->header);
    free(parsed->text_header);
    free(parsed->target_func);
    free(parsed->symtab_header);
    free(parsed);
}
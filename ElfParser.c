#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf64.h"
#include "ElfParser.h"

ParsedElf *parse(const char *path_to_elf, const char *target_func_name)
{
    ParsedElf *parsed = malloc(sizeof(ParsedElf));
    parsed->found_symbol=0;
    parse_elf_header(parsed, path_to_elf);
    parse_section_headers(parsed, path_to_elf);
    parse_symbol_entry(parsed, path_to_elf, target_func_name);
    get_func_adress(parsed);
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
    fclose(file);
}

void parse_section_headers(ParsedElf *parsedElf, const char *path_to_elf)
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
    } while (strcmp(get_section_name(parsedElf, path_to_elf, text_header), ".text") && i < parsedElf->header->e_shnum);

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
    } while (strcmp(get_section_name(parsedElf, path_to_elf, symtab_header), ".symtab") && i < parsedElf->header->e_shnum);

    Elf64_Shdr *string_header = malloc(sizeof(Elf64_Shdr));
    fseek(file, (*parsedElf).header->e_shoff, SEEK_SET);
    i = 0;
    do
    {
        int read_res = fread(string_header, sizeof(Elf64_Ehdr), 1, file);
        if (read_res == 0)
        {
            fprintf(stderr, "Failed reading the header of the following file : '%s'\n", path_to_elf);
            return;
        }
        i++;
    } while (strcmp(get_section_name(parsedElf, path_to_elf, string_header), ".strtab") && i < parsedElf->header->e_shnum);

    (*parsedElf).text_header = text_header;
    (*parsedElf).symtab_header = symtab_header;
    (*parsedElf).string_header = string_header;
    fclose(file);
}

void parse_symbol_entry(ParsedElf *parsedElf, const char *path_to_elf, const char *target_func_name)
{
    FILE *file = fopen(path_to_elf, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed opening the following file : '%s'\n", path_to_elf);
        return;
    }
    int num_of_symbols = parsedElf->symtab_header->sh_size / sizeof(Elf64_Sym);
    int i = 0;
    Elf64_Sym *symbol = malloc(sizeof(Elf64_Sym));
    fseek(file, parsedElf->symtab_header->sh_offset, SEEK_SET);
    do
    {
        int read_res = fread(symbol, sizeof(Elf64_Sym), 1, file);
        if (read_res == 0)
        {
            fprintf(stderr, "Failed reading the header of the following file : '%s'\n", path_to_elf);
            return;
        }
        i++;
    } while (strcmp(get_symbol_name(parsedElf, path_to_elf, symbol), target_func_name) && i < num_of_symbols);

    if (!strcmp(get_symbol_name(parsedElf, path_to_elf, symbol), target_func_name))
    {
        parsedElf->found_symbol = 1;
    }
    (*parsedElf).target_func = symbol;
    fclose(file);
}

char *get_symbol_name(ParsedElf *parsed, const char *path_to_elf, Elf64_Sym *symbol)
{
    char temp[100];
    FILE *file = fopen(path_to_elf, "rb");
    fseek(file, parsed->string_header->sh_offset + symbol->st_name, SEEK_SET);
    char ch;
    int i = 0;
    do
    {
        ch = fgetc(file);
        temp[i] = ch;
        i++;
    } while (i < 100);
    char *name = malloc((i + 1) * sizeof(char));
    strcpy(name, temp);
    fclose(file);
    return name;
}

void *get_func_adress(ParsedElf *parsed)
{
    void *address = (void *)parsed->target_func->st_value;
    parsed->br_address = address;
    return address;
}

char *get_section_name(ParsedElf *parsed, const char *path_to_elf, Elf64_Shdr *section)
{
    char temp[100];
    FILE *file = fopen(path_to_elf, "rb");
    fseek(file, (*parsed).header->e_shoff + sizeof(Elf64_Shdr) * ((*parsed).header->e_shstrndx), SEEK_SET);
    Elf64_Shdr *shstrndx = malloc(sizeof(Elf64_Shdr));
    int read_res = fread(shstrndx, sizeof(Elf64_Shdr), 1, file);
    fseek(file, shstrndx->sh_offset + section->sh_name, SEEK_SET);
    char ch;
    int i = 0;
    do
    {
        ch = fgetc(file);
        temp[i] = ch;
        i++;
    } while (ch != '\0' && i < 100);
    char *name = malloc((i + 1) * sizeof(char));
    strcpy(name, temp);
    fclose(file);
    free(shstrndx);
    return name;
}

int get_func_bind_prop(ParsedElf *parsed)
{
    return ELF64_ST_BIND(parsed->target_func->st_info);
}

int is_symbol_function(Elf64_Sym *symbol) {
    return ELF64_ST_TYPE(symbol->st_info) == STT_FUNC;
}


void destroy(ParsedElf *parsed)
{
    free(parsed->header);
    free(parsed->text_header);
    free(parsed->target_func);
    free(parsed->symtab_header);
    free(parsed);
}
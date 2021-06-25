#include <stdio.h>
#include "elf64.h"
#include "ElfParser.h"


ParsedElf* parse(const char* path_to_elf, const char* target_func_name) {
    ParsedElf *parsed = malloc(sizeof(ParsedElf));
    parse_elf_header(parsedElf, path_to_elf);
    parse_text_header(parsedElf, path_to_elf);
    parse_symbol_entry(parsedElf,path_to_elf, target_func_name);
    return parsed;
}

void parse_elf_header(Elf64_Phdr* parsedElf, const char* path_to_elf) {
    Elf64_Ehdr* header = malloc(sizeof(Elf64_Ehdr));
    FILE* file = fopen(path_to_elf,"rb");
    if (file==NULL){
        fprintf(stderr,"Failed opening the following file : '%s'\n",elf_file);
    return NULL;
    }
    read_res = fread(header,sizeof(Elf64_Ehdr),1,file);
    if (read_res==0){
        fprintf(stderr,"Failed reading the header of the following file : '%s'\n",elf_file);
        return NULL;
    }


}

void parse_text_header(Elf64_Phdr* parsedElf, const char* path_to_elf) {
    Elf64_Phdr* pheader = malloc(sizeof(Elf64_Phdr));
    FILE* file = fopen(path_to_elf,"rb");
    if (file==NULL){
        fprintf(stderr,"Failed opening the following file : '%s'\n",elf_file);
        return NULL;
    }
    (*parsedElf).pheader = *pheader;
}

void parse_symbol_entry(Elf64_Sym* parsedElf, const char* target_func_name) {
    return;
}











void* elf_parser(const char* elf_file,const char* func_to_find){
    FILE* file = fopen(elf_file,"rb");

    Elf64_Ehdr* header;
    int read_res;
    read_res = fread(header,sizeof(Elf64_Ehdr),1,file);
    if (read_res==0){
        fprintf(stderr,"Failed reading the header of the following file : '%s'\n",elf_file);
        return NULL;
    }
    Elf64_Shdr* symbol_table;
    read_res = fread(symbol_table,sizeof())
    if (read_res==0){
        fprintf(stderr,"Failed reading the header of the following file : '%s'\n",elf_file);
        return NULL;
    }

}
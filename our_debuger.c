#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "elf64.h"

void* elf_parser(const char* elf_file,const char* func_to_find){
    FILE* file = fopen(elf_file,"rb");
    if (file==NULL){
        fprintf(stderr,"Failed opening the following file : '%s'\n",elf_file);
        return NULL;
    }
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
pid_t execute_program(const char* exec_file){
    int pid = fork();
    if (pid>0){//father code
        return pid;
    }
    else if (pid==0){//child code
        if (ptrace(PTRACE_TRACEME,getpid(),NULL,NULL)<0){
            perror("ptrace");
            exit(1);
        }
        execl(exec_file,exec_file);
    }
    else{
        perror("fork");
        exit(1);
    }
}
void run_syscall_fix_debugger(pid_t debugged_pid, void* func_addr){
    int wait_status;
    waitpid(debugged_pid,&wait_status,NULL);
    while (WIFSTOPPED(wait_status)){
        ptrace(PTRACE_PEEKTEXT,debugged_pid,func_addr,)
        if (ptrace(PTRACE_SIN))
    }
        
}
int main(int argc,char *argv[]){
    const char* func_name = argv[1];
    const char* program_to_debug = argv[2];
    void* func_addr=elf_parser(program_to_debug,func_name);
    pid_t debugged_pid = execute_program(program_to_debug);
    run_syscall_fix_debugger(debugged_pid, func_addr);
    return 0;
}
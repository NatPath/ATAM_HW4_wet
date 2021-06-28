#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <stdlib.h>
#include "elf64.h"
#include "ElfParser.h"

#define SYSCALL_OPC_V1 0x0F05
#define SYSCALL_OPC_V2 0X050F
// Ptace
// include ./parser

/**

1. parse Elf File.
2. set br to the correct offset (func. name)
3. sniff instr - catch syscalls, untill func defintion ends.
    3.1 - read regs
    3.2 make sure output is correct / no exepctions found
4    
*/
#define DO_SYS_RET( SYSCALL , RET_VALUE) do {\
    RET_VALUE = SYSCALL ;\
    if (RET_VALUE == -1){\
        exit(1);\
    }\
}while(0)\

#define DO_SYS( SYSCALL) do {\
    if (SYSCALL == -1){\
        exit(1);\
    }\
}while(0)\

void debug(int i, pid_t pid) {
    struct user_regs_struct regs;
    DO_SYS(ptrace(PTRACE_GETREGS, pid,0,&regs));
    long instr ;
    DO_SYS_RET(ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0),instr);
    printf("-----%d-----\n", i);
    printf("RIP = %p\n", (void*)regs.rip);
    printf("INSTRUCTION = 0x%lx\n", instr);
    printf("RDI = 0x%llx\n", regs.rdi);
} 

pid_t execute_program(const char *exec_file,char* argv[])
{
    int pid = fork();
    if (pid > 0)
    { //father code
        return pid;
    }
    else if (pid == 0)
    { //child code
        if (ptrace(PTRACE_TRACEME, getpid(), NULL, NULL) < 0)
        {
            exit(1);
            perror("ptrace");
            exit(1);
        }
        execv(exec_file, argv);
    }
    else
    {
        exit(1);
        perror("fork");
        exit(1);
    }
}
// in a stopped proccess, get the current rip
void *getRip(pid_t debugged_pid)
{
    struct user_regs_struct regs;
    DO_SYS(ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs));
    return (void*)(regs.rip-1);
}


unsigned long generate_br_INT_3(long data) {
    return (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
}

void insert_breakpoint_at_target_function(void *func_addr, pid_t debugged_pid, long* data) {
        //*data = ptrace(PTRACE_PEEKTEXT, debugged_pid, func_addr, NULL);
        DO_SYS_RET(ptrace(PTRACE_PEEKTEXT, debugged_pid, func_addr, NULL),*data);
        unsigned long data_trap = generate_br_INT_3(*data);
        DO_SYS(ptrace(PTRACE_POKETEXT, debugged_pid, func_addr, (void *)data_trap));
        
}

long insert_breakpoint_at_ret_inst(void *func_addr, pid_t debugged_pid, void **rsp, long* data_ret) {
    struct user_regs_struct regs;
    DO_SYS(ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs));
    *rsp = (void*)regs.rsp;
    long return_to_rip;
    DO_SYS_RET(ptrace(PTRACE_PEEKDATA, debugged_pid, *rsp, NULL),return_to_rip);
    DO_SYS_RET(ptrace(PTRACE_PEEKTEXT, debugged_pid, return_to_rip, NULL),*data_ret);
    unsigned long data_trap = generate_br_INT_3(*data_ret);
    DO_SYS(ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, (void *)data_trap));
    return return_to_rip;  
}
// is inst a syscall
bool is_syscall(unsigned short inst){
    return (inst == SYSCALL_OPC_V1 || inst == SYSCALL_OPC_V2);
}
bool was_the_last_instruction_syscall(pid_t pid){
    struct user_regs_struct regs;
    DO_SYS(ptrace(PTRACE_GETREGS,pid,0,&regs));
    long instr;
    DO_SYS_RET(ptrace(PTRACE_PEEKDATA,pid,regs.rip-2,0),instr);
    return is_syscall((unsigned short)instr);
}

//gets intrustion of 2 bytes before to check if it is a syscall
bool is_br_whitelisted(void* rip, void* ret_address,pid_t pid) {
     return was_the_last_instruction_syscall(pid) || rip == ret_address; 
}

void rip_decrease(pid_t debugged_pid){
    struct user_regs_struct regs;
    DO_SYS(ptrace(PTRACE_GETREGS,debugged_pid,0,&regs));
    regs.rip--;
    DO_SYS(ptrace(PTRACE_SETREGS,debugged_pid,0,&regs));
    
}
void handle_syscall(pid_t debugged_pid){
    long syscall_return_val;
    void* syscall_rip;
    struct user_regs_struct regs;
    DO_SYS(ptrace(PTRACE_GETREGS, debugged_pid, 0, &regs));
    syscall_return_val = regs.rax;
    syscall_rip = (void*)(regs.rip-2);
    if (syscall_return_val < 0) {
        printf("PRF:: syscall in %llx returned with %ld\n", (long long unsigned int)syscall_rip, syscall_return_val);
    }
}

void track_syscalls(pid_t debugged_pid, void* func_address, void* ret_address, void* rsp,long data,long data_ret, int *wait_status){
    struct user_regs_struct regs;
    long current_instruction;// 8 bytes of the instruction
    unsigned short shortened_instruction;// only 2 bytes of the instruction
    void* current_rip;
    void* current_rsp;
    //unsigned long long int syscall_return_val;
    /*
    void* data_trap;
    void* data_ret_trap;
    */
    unsigned long data_trap = generate_br_INT_3(data);
    unsigned long data_ret_trap = generate_br_INT_3(data_ret);

    

    DO_SYS(ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL));
    DO_SYS(waitpid(debugged_pid, wait_status, 0));
    int i = 0;
    while(WIFSTOPPED(*wait_status) && !(WIFEXITED(*wait_status) || WIFSIGNALED(*wait_status))){
        i++;
        DO_SYS(ptrace(PTRACE_GETREGS, debugged_pid,0,&regs));
        current_rip = (void*)(regs.rip-1);
        current_rsp = (void*)regs.rsp;
        //current_instruction = ptrace(PTRACE_PEEKTEXT, debugged_pid, regs.rip-1,0);
        DO_SYS_RET(ptrace(PTRACE_PEEKTEXT, debugged_pid, regs.rip-1,0),current_instruction);
        shortened_instruction=(unsigned short)current_instruction;
        if (is_br_whitelisted(current_rip, ret_address,debugged_pid)) {
            if (current_rip == ret_address) {  
                if(current_rsp == rsp + 8) {// true = we're out
                    DO_SYS(ptrace(PTRACE_POKETEXT, debugged_pid,ret_address,(void*)data_ret));
                    rip_decrease(debugged_pid);
                    return;
                }
                else { //we are in
                    DO_SYS(ptrace(PTRACE_POKETEXT, debugged_pid,ret_address,(void*)data_ret));
                    rip_decrease(debugged_pid);
                    if(is_syscall((unsigned short)data_ret)){
                        DO_SYS(ptrace(PTRACE_SINGLESTEP,debugged_pid,0,0));
                        DO_SYS(waitpid(debugged_pid, wait_status, 0));
                        handle_syscall(debugged_pid);
                    }
                    DO_SYS(ptrace(PTRACE_POKETEXT, debugged_pid, ret_address, (void*)data_ret_trap));
                }
            } else { // we're in -> MUST BE A SYSCALL
                    DO_SYS(ptrace(PTRACE_SYSCALL,debugged_pid,0,0));
                    DO_SYS(waitpid(debugged_pid, wait_status, 0));
                    if ((WIFEXITED(*wait_status) || WIFSIGNALED(*wait_status))){
                        return;
                    }
                    handle_syscall(debugged_pid);
            }
        }
        DO_SYS(ptrace(PTRACE_SYSCALL,debugged_pid,0,0));
        DO_SYS(waitpid(debugged_pid, wait_status, 0));
    }
    return;
}


void run_syscall_fix_debugger(pid_t debugged_pid, void *func_addr)
{
    int wait_status;
    void *rsp;
    long data; // backup of the first command of func (overwritten by int 3)
    long data_ret; // backup of the next command after func call (overwritten by int 3)
    int i=0;

    DO_SYS(waitpid(debugged_pid, &wait_status, 0));
    while(WIFSTOPPED(wait_status) && !(WIFEXITED(wait_status) || WIFSIGNALED(wait_status))){
        i++;
        insert_breakpoint_at_target_function(func_addr, debugged_pid, &data);
        DO_SYS(ptrace(PTRACE_CONT, debugged_pid, NULL, NULL));
        DO_SYS(wait(&wait_status));
        if (!WIFEXITED(wait_status) && WIFSTOPPED(wait_status)) {
            if(func_addr == getRip(debugged_pid)) {
                //return_original_function(func_addr,debugged_pid,data);
                DO_SYS(ptrace(PTRACE_POKETEXT,debugged_pid,func_addr,data));
                rip_decrease(debugged_pid);
                long ret_address = insert_breakpoint_at_ret_inst(func_addr, debugged_pid, &rsp, &data_ret);
                track_syscalls(debugged_pid, func_addr, (void*)ret_address, rsp, data, data_ret, &wait_status);
            }
        }  
    }
}

int main(int argc, char *argv[])
{
    const char *func_name = argv[1];
    const char *program_to_debug = argv[2];
    char** argv_modified=(char**)malloc(argc*sizeof(char*)+1);
    for (int i=2;i<argc;i++){
        argv_modified[i-2]=argv[i];

    }
    argv_modified[argc] = (char*)NULL;
    ParsedElf *parsed_elf = parse(program_to_debug, func_name);
    if (parsed_elf->found_symbol != 1)
    {
        printf("PRF:: not found!\n");
        return 0;
    }
    if (get_func_bind_prop(parsed_elf) == STB_LOCAL)
    {
        printf("PRF:: local found!\n");
        return 0;
    }
    if (get_func_bind_prop(parsed_elf) == STB_GLOBAL)
    {
        pid_t debugged_pid = execute_program(program_to_debug,argv_modified);
        void *func_addr = parsed_elf->br_address;
        run_syscall_fix_debugger(debugged_pid, func_addr);
    }
    destroy(parsed_elf);
    free(argv_modified);
    return 0;
}
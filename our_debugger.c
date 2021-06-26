#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>

#include "elf64.h"
#include "ElfParser.h"
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
    struct user_regs_struct regs;
    while (WIFSTOPPED(wait_status)){
        int call_balance=0;
        // backup original command
        long data = ptrace(PTRACE_PEEKTEXT,debugged_pid,func_addr,NULL);
        
        // writes the break point (injects int 3 in the func_addr)
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, debugged_pid, func_addr,(void*)data_trap);        
        
        ptrace(PTRACE_CONT, debugged_pid, NULL,NULL);
        waitpid(debugged_pid,&wait_status,NULL);
        if (WIFSTOPPED(wait_status)){
            //inside the function
            
            ptrace(PTRACE_SYSCALL,debugged_pid,NULL,NULL);
            waitpid(debugged_pid,&wait_status,NULL);
            while (WIFSTOPPED(wait_status)){
                if (!is_inside_func()){

                    break;
                }
                if (stopped_at_call()){
                    call_balance++;
                    ptrace(PTRACE_SYSCALL,debugged_pid,NULL,NULL);
                    waitpid(debugged_pid,&wait_status,NULL);

                }
                if (stopped_at_ret()){
                    if (call_balance==0){
                        ptrace(PTRACE_SYSCALL,debugged_pid,NULL,NULL);
                        waitpid(debugged_pid,&wait_status,NULL);
                        break;
                    }
                    call_balance--;
                    ptrace(PTRACE_SYSCALL,debugged_pid,NULL,NULL);
                    waitpid(debugged_pid,&wait_status,NULL);
                }
                else{ // stopped at syscall
                    // do_da_thing(); // get the regs print "PRF::syscall in <hex syscall address> returned with <decimal return value>"
                    ptrace(PTRACE_GETREGS, debugged_pid,0,&regs);
                    unsigned long long int syscall_rip = regs.rip;

                    ptrace(PTRACE_SINGLESTEP,debugged_pid,0,0);
                    ptrace(PTRACE_GETREGS, debugged_pid,0,&regs);

                    unsigned long long int syscall_return_val = regs.rax;
                    printf("PRF::syscall in %p returned with %llu\n", syscall_rip,syscall_return_val);
                    ptrace(PTRACE_SYSCALL,debugged_pid,NULL,NULL);
                    waitpid(debugged_pid,&wait_status,NULL);
                }
            }

        }

        waitpid(debugged_pid,&wait_status,NULL);
    }
}

int main(int argc,char *argv[]){
    const char* func_name = argv[1];
    const char* program_to_debug = argv[2];
    ParsedElf* parsed_elf= parse(program_to_debug,func_name); 
    void* func_addr=elf_parser(program_to_debug,func_name);
    if (func_addr==NULL){
        printf("PRF::not found!\n");
        return 0;
    }
    pid_t debugged_pid = execute_program(program_to_debug);
    run_syscall_fix_debugger(debugged_pid, func_addr);
    return 0;
}
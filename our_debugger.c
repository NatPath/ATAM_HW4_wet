#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <stdlib.h>
#include "elf64.h"
#include "ElfParser.h"

#define SYSCALL_OPCODE 0x0f05
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

pid_t execute_program(const char *exec_file)
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
            perror("ptrace");
            exit(1);
        }
        execl(exec_file, exec_file);
    }
    else
    {
        perror("fork");
        exit(1);
    }
}
// in a stopped proccess, get the current rip
void *getRip(pid_t debugged_pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs);
    return (void*)(regs.rip-1);
}
void run_syscall_fix_debugger(pid_t debugged_pid, void *func_addr)
{
    int wait_status;
    struct user_regs_struct regs;
    void *rsp;
    waitpid(debugged_pid, &wait_status, 0);
    while (WIFSTOPPED(wait_status))
    {
        // backup original first command of func
        long data = ptrace(PTRACE_PEEKTEXT, debugged_pid, func_addr, NULL);

        // writes the break point (injects int 3 in the func_addr)
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, debugged_pid, func_addr, (void *)data_trap);

        ptrace(PTRACE_CONT, debugged_pid, NULL, NULL);
        waitpid(debugged_pid, &wait_status, 0);
        if (WIFSTOPPED(wait_status))
        {
            void *rip = getRip(debugged_pid);
            printf("rip is: %p\n",rip);
            printf("func_addr is %p\n",func_addr);
            if (rip == func_addr)
            { // entered the function
                //return the original function of the breakpoint
                ptrace(PTRACE_POKETEXT, debugged_pid, func_addr, data);
                //make a breakpoint in the return address
                ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs);
                rsp = (void*)regs.rsp;
                long return_to_rip = ptrace(PTRACE_PEEKDATA, debugged_pid, rsp, NULL);
                long data_ret = ptrace(PTRACE_PEEKTEXT, debugged_pid, return_to_rip, NULL);
                data_trap = (data_ret & 0xFFFFFFFFFFFFFF00) | 0xCC;
                ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, (void *)data_trap);

                ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                waitpid(debugged_pid, &wait_status, 0);
                while (WIFSTOPPED(wait_status))
                {
                    //check where we stopped
                    ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs);
                    regs.rip--;
                    long inst = ptrace(PTRACE_PEEKTEXT, debugged_pid, regs.rip, NULL);
                    printf("rip is now : %0llx\n",regs.rip);
                    printf("inst is : %0lx\n", inst);
                    if (inst == SYSCALL_OPCODE)
                    {
                        // stopped at syscall
                        void* syscall_rip = getRip(debugged_pid);
                        ptrace(PTRACE_SINGLESTEP, debugged_pid, 0, 0); //do the syscall

                        ptrace(PTRACE_GETREGS, debugged_pid, 0, &regs);
                        unsigned long long int syscall_return_val = regs.rax;
                        printf("PRF::syscall in %p returned with %llu\n", syscall_rip, syscall_return_val);

                        ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                        waitpid(debugged_pid, &wait_status, 0);
                        continue;
                    }
                    /*
                    if (getRip(debugged_pid) == func_addr)
                    {
                        //stopped at the beginning of func for some reason (probably recursion)
                        //just continue to the next syscall i guess?
                        ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                        waitpid(debugged_pid, &wait_status, NULL);
                        continue;
                    }
                    */
                    if (getRip(debugged_pid) == (void*)return_to_rip)
                    {
                        //check if we're just out of the function
                        ptrace(PTRACE_GETREGS, debugged_pid,NULL,&regs);
                        if (rsp==(void*)regs.rsp){
                            ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, data_ret);
                            break;
                        }
                        else{ //we landed on return_to_rip but havn't gotten out of the function yet 
                            ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, data_ret);
                            ptrace(PTRACE_SINGLESTEP, debugged_pid, NULL, NULL);
                            ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, data_trap);
                            ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                            waitpid(debugged_pid,&wait_status,0);
                        }
                                                
                    }
                    else
                    {
                        //stopped for other unknown reason. might be a user breakpoint or some interupt
                        ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                        waitpid(debugged_pid, &wait_status, 0);
                    }
                }
            }
            else
            { //another breakpoint
                ptrace(PTRACE_CONT, debugged_pid, NULL, NULL);
                waitpid(debugged_pid, &wait_status, 0);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    const char *func_name = argv[1];
    const char *program_to_debug = argv[2];
    ParsedElf *parsed_elf = parse(program_to_debug, func_name);
    if (parsed_elf->found_symbol != 1)
    {
        printf("PRF::not found!\n");
        return 0;
    }
    if (get_func_bind_prop(parsed_elf) == STB_LOCAL)
    {
        printf("PRF::local found!\n");
        return 0;
    }
    if (get_func_bind_prop(parsed_elf) == STB_GLOBAL)
    {
        pid_t debugged_pid = execute_program(program_to_debug);
        void *func_addr = parsed_elf->br_address;
        run_syscall_fix_debugger(debugged_pid, func_addr);
    }
    return 0;
}
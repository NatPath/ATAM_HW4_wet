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

#define SYSCALL_OPCODE 0x050f
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


unsigned long generate_br_INT_3(long data) {
    return (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
}

void insert_breakpoint_at_target_function(void *func_addr, pid_t debugged_pid, long* data) {
        *data = ptrace(PTRACE_PEEKTEXT, debugged_pid, func_addr, NULL);
        unsigned long data_trap = generate_br_INT_3(*data);
        ptrace(PTRACE_POKETEXT, debugged_pid, func_addr, (void *)data_trap);
}

long insert_breakpoint_at_ret_inst(void *func_addr, pid_t debugged_pid, void **rsp, long* data_ret) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs);
    rsp = (void*)regs.rsp;
    long return_to_rip = ptrace(PTRACE_PEEKDATA, debugged_pid, rsp, NULL);
    *data_ret = ptrace(PTRACE_PEEKTEXT, debugged_pid, return_to_rip, NULL);
    unsigned long data_trap = generate_br_INT_3(*data_ret);
    ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, (void *)data_trap);  
    return return_to_rip;  
}

bool is_br_whitelisted(void* rip, void* ret_address,unsigned short instr) {
     return instr == SYSCALL_OPCODE || rip == ret_address; 
}

void rip_decrease(pid_t debugged_pid){
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS,debugged_pid,0,&regs);
    regs.rip--;
    ptrace(PTRACE_SETREGS,debugged_pid,0,&regs);
    
}
void handle_syscall(pid_t debugged_pid){
    long syscall_return_val;
    void* syscall_rip;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, debugged_pid, 0, &regs);
    syscall_return_val = regs.rax;
    syscall_rip = (void*)(regs.rip-2);
    printf("PRF::syscall in %p returned with %ld\n", syscall_rip, syscall_return_val);

}

void debug(int i, pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid,0,&regs);
    long instr  = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0);
    printf("-----%d-----\n", i);
    printf("RIP = %p\n", (void*)regs.rip);
    printf("INSTRUCTION = 0x%lx\n", instr);

} 

void track_syscalls(pid_t debugged_pid, void* func_address, void* ret_address, void* rsp,long data,long data_ret){
    int wait_status;
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

    

    ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
    waitpid(debugged_pid, &wait_status, 0);
    int i = 0;
    while(WIFSTOPPED(wait_status)){
        i++;
        //printf("entered the loop for the %dth time\n",i+1);
        ptrace(PTRACE_GETREGS, debugged_pid,0,&regs);
        current_rip= (void*)(regs.rip-1);
        current_rsp= (void*)regs.rsp;
        current_instruction = ptrace(PTRACE_PEEKTEXT, debugged_pid, regs.rip-1,0);
        shortened_instruction=(unsigned short)current_instruction;
        debug(i,debugged_pid);
        if (is_br_whitelisted(current_rip, ret_address,shortened_instruction)) {
            if (current_rip == ret_address) {
                if(current_rsp == rsp+8 ) {// true = we're out
                    return;
                }
                else { //we are in
                    printf("we're still in\n");
                    //1. reinject original ret_instr
                    ptrace(PTRACE_POKETEXT, debugged_pid,ret_address,(void*)data_ret);
                    //2. exec instr
                    //3. print shit if syscall
                    //check_if_syscall();
                    rip_decrease(debugged_pid);
                    printf("data_ret is : %04x\n",(unsigned short)data_ret);
                    if ((unsigned short)data_ret == SYSCALL_OPCODE || (unsigned short)data_ret == 0x0f05){
                        ptrace(PTRACE_SINGLESTEP, debugged_pid ,0 ,0);
                        waitpid(debugged_pid, &wait_status, 0);
                        handle_syscall(debugged_pid);
                    }
                    //4. reinject br
                    debug(i, debugged_pid);
                    printf("trap: %lu", data_trap);
                    ptrace(PTRACE_POKETEXT, debugged_pid, ret_address, (void*)data_trap);
                    debug(i,debugged_pid);
                }
            } else { // we're in -> MUST BE A SYSCALL
                    //1. exec instr
                    ptrace(PTRACE_SINGLESTEP, debugged_pid, 0, 0); //do the syscall
                    handle_syscall(debugged_pid);
            }
        }
        ptrace(PTRACE_SYSCALL,debugged_pid,0,0);
        waitpid(debugged_pid, &wait_status, 0);
    }
}


void run_syscall_fix_debugger(pid_t debugged_pid, void *func_addr)
{
    int wait_status;
    void *rsp;
    long data; // backup of the first command of func (overwritten by int 3)
    long data_ret; // backup of the next command after func call (overwritten by int 3)

    waitpid(debugged_pid, &wait_status, 0);
    while(WIFSTOPPED(wait_status)){
        insert_breakpoint_at_target_function(func_addr, debugged_pid, &data);
        ptrace(PTRACE_CONT, debugged_pid, NULL, NULL);
        waitpid(debugged_pid, &wait_status, 0);
        if (WIFSTOPPED(wait_status)) {
            if(func_addr == getRip(debugged_pid)) {
                printf("Entered the function\n");
                long ret_address = insert_breakpoint_at_ret_inst(func_addr, debugged_pid, &rsp, &data_ret);
                track_syscalls(debugged_pid, func_addr, (void*)ret_address, rsp, data, data_ret);
            }
        }  
    }
}

/*
void run_syscall_fix_debugger(pid_t debugged_pid, void *func_addr)
{
    int wait_status;
    struct user_regs_struct regs;
    void *rsp;
    long current_instruction;
    void* current_rip;
    long data; // backup of the first command of func (overwritten by int 3)
    long data_ret; // backup of the next command after func call (overwritten by int 3)
    unsigned long data_trap; // a mask for injecting int 3 into a command
    long return_to_rip; // the rip of the next command after func call
    unsigned short instruction_shortened;

    waitpid(debugged_pid, &wait_status, 0);
    while (WIFSTOPPED(wait_status))
    {
        // backup original first command of func
        data = ptrace(PTRACE_PEEKTEXT, debugged_pid, func_addr, NULL);

        // writes the break point (injects int 3 in the func_addr)
        data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, debugged_pid, func_addr, (void *)data_trap);
        

        ptrace(PTRACE_CONT, debugged_pid, NULL, NULL);
        waitpid(debugged_pid, &wait_status, 0);
        if (WIFSTOPPED(wait_status))
        {
            current_rip = getRip(debugged_pid);
            printf("--First stop of traced--\n");
            printf("rip is: %p\n",current_rip);
            printf("func_addr is %p\n",func_addr);
            printf("\n");
            if (current_rip == func_addr)
            { // entered the function
                //return the original command of the breakpoint
                //make a breakpoint in the return address
                ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs);
                rsp = (void*)regs.rsp;
                return_to_rip = ptrace(PTRACE_PEEKDATA, debugged_pid, rsp, NULL);
                data_ret = ptrace(PTRACE_PEEKTEXT, debugged_pid, return_to_rip, NULL);
                data_trap = (data_ret & 0xFFFFFFFFFFFFFF00) | 0xCC;
                ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, (void *)data_trap);


                ptrace(PTRACE_POKETEXT, debugged_pid, func_addr, data);
                // sets rip 1 byte backwards
                regs.rip-=1;
                ptrace(PTRACE_SETREGS,debugged_pid,0,regs);
                ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                waitpid(debugged_pid, &wait_status, 0);
                while (WIFSTOPPED(wait_status))
                {
                    //check where we stopped
                    ptrace(PTRACE_GETREGS, debugged_pid, NULL, &regs);
                    current_rip = getRip(debugged_pid);
                    printf("rip is now : %p\n",current_rip);
                    current_instruction = ptrace(PTRACE_PEEKDATA, debugged_pid, current_rip,NULL);
                    instruction_shortened= (unsigned short)current_instruction;
                    printf("the byte in rip is: %hhx\n" ,instruction_shortened);
                    printf("instruction shortened is : %c\n",instruction_shortened);
                    //current_instruction= ptrace(PTRACE_PEEKTEXT, debugged_pid, regs.rip, NULL);
                    printf("rip is now : %0llx\n",regs.rip);
                    printf("inst is : %0x\n", (short)current_instruction);
                    if (current_rip == (void*)return_to_rip)
                    {
                        printf("You stopped at return_to_rip!\n");
                        if (instruction_shortened==0xcc ){
                            //meaning we stopped because of int 3 that we have planted
                            printf("You stopped at 0xcc\n");
                            //put back the original command
                            regs.rip--;
                            ptrace(PTRACE_SETFPREGS,debugged_pid,0,regs);
                            ptrace(PTRACE_POKETEXT,debugged_pid,return_to_rip,data_ret);
                        }
                        //check if we're just out of the function
                        ptrace(PTRACE_GETREGS, debugged_pid,NULL,&regs);
                        if (rsp==(void*)(regs.rsp-8)){
                            printf("It means you're really out of the function, HURRAY\n");
                            break;
                        }
                        else{ //we landed on return_to_rip but havn't gotten out of the function yet 
                            printf("we landed on return_to_rip but havn't gotten out of the function yet\n");
                            // current_instruction =ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, data_ret);
                            printf("lets see whats going on:\n");
                            printf("instruction shortend is : %c\n",instruction_shortened );
                            if (instruction_shortened==0x05cc){
                                printf("this is syscall!!\n");
                            }
                            ptrace(PTRACE_SINGLESTEP, debugged_pid, NULL, NULL);
                            ptrace(PTRACE_POKETEXT, debugged_pid, return_to_rip, data_trap);
                            ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                            waitpid(debugged_pid,&wait_status,0);
                            continue;
                        }
                                                
                    }
                    if (current_instruction == SYSCALL_OPCODE)
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
                    if (getRip(debugged_pid) == func_addr)
                    {
                        //stopped at the beginning of func for some reason (probably recursion)
                        //just continue to the next syscall i guess?
                        ptrace(PTRACE_SYSCALL, debugged_pid, NULL, NULL);
                        waitpid(debugged_pid, &wait_status, NULL);
                        continue;
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

*/



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
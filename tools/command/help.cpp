#include <iostream>
#include <vector>

#include "handlers.hpp"

namespace xdb_handlers {

void print_help(std::span<const std::string> args) {
    if (args.size() == 1) {
        std::cout << "Available commands:\n"
                  << "    help, h            - Show this help message\n"
                  << "    breakpoint, b      - Manage breakpoints\n"
                  << "    catchpoint, catch  - Manage catchpoints (syscalls)\n"
                  << "    continue, c        - Resume the process\n"
                  << "    disassemble, disas - Disassemble instructions\n"
                  << "    memory, mem        - Memory operations\n"
                  << "    register, reg      - Register operations\n"
                  << "    stepi, si          - Single step an instruction\n"
                  << "    watchpoint, w      - Manage watchpoints\n";
    } else if (args[1] == "breakpoint" || args[1] == "b") {
        std::cout << "Manage breakpoints.\n"
                  << "Usage:\n"
                  << "    breakpoint list             - List all breakpoints\n"
                  << "    breakpoint set <address>    - Set a breakpoint at the specified address\n"
                  << "    breakpoint set <address> --hardware/-h"
                  << "                                - Set a hardware breakpoint at the specified address\n"
                  << "    breakpoint enable <id>      - Enable a breakpoint by ID\n"
                  << "    breakpoint disable <id>     - Disable a breakpoint by ID\n"
                  << "    breakpoint delete <id>      - Delete a breakpoint by ID\n";
    } else if (args[1] == "catchpoint" || args[1] == "catch") {
        std::cout << "Manage catchpoints for syscalls.\n"
                  << "Usage:\n"
                  << "    catchpoint syscall                    - Catch all syscalls\n"
                  << "    catchpoint sys none                   - Stop catching syscalls\n"
                  << "    catchpoint sys <name>                 - Catch specific syscall by name\n"
                  << "    catchpoint syscall <number>           - Catch specific syscall by number\n"
                  << "    catchpoint sys <name1>,<name2>,...    - Catch multiple syscalls\n"
                  << "Examples:\n"
                  << "    catch syscall                         - Catch all syscalls\n"
                  << "    catch sys none                        - Stop catching syscalls\n"
                  << "    catch sys write                       - Catch write syscall\n"
                  << "    catch syscall 1                       - Catch syscall number 1\n"
                  << "    catch sys write,read,openat           - Catch multiple syscalls\n"
                  << "    catch sys 0,ptrace                    - Catch syscalls 0 and ptrace\n";
    } else if (args[1] == "watchpoint" || args[1] == "w") {
        std::cout << "Manage watchpoints.\n"
                  << "Usage:\n"
                  << "    watchpoint list                        - List all watchpoints\n"
                  << "    watchpoint set <address> <mode> <size> - Set a watchpoint\n"
                  << "    watchpoint enable <id>                 - Enable a watchpoint by ID\n"
                  << "    watchpoint disable <id>                - Disable a watchpoint by ID\n"
                  << "    watchpoint delete <id>                 - Delete a watchpoint by ID\n"
                  << "Modes:\n"
                  << "    write                                  - Break on write access\n"
                  << "    read_write, rw                         - Break on read or write access\n"
                  << "    execute                                - Break on execution\n"
                  << "Size:\n"
                  << "    1, 2, 4, 8                             - Number of bytes to watch\n"
                  << "Examples:\n"
                  << "    watchpoint set 0x401000 write 4\n"
                  << "    watchpoint set 0x7fff12345678 read_write 8\n";
    } else if (args[1] == "continue" || args[1] == "c") {
        std::cout << "Resume the process.\n";
    } else if (args[1] == "disassemble" || args[1] == "disas") {
        std::cout << "Disassemble instructions.\n"
                  << "Usage:\n"
                  << "    disassemble [-c <count>] [-a <address>]\n"
                  << "    disas [-c <count>] [-a <address>]\n"
                  << "Options:\n"
                  << "    -c <count>     - Number of instructions to disassemble (default: 5)\n"
                  << "    -a <address>   - Starting address (default: current PC)\n"
                  << "Examples:\n"
                  << "    disas\n"
                  << "    disas -c 10\n"
                  << "    disas -a 0x401000\n"
                  << "    disas -c 8 -a 0x401000\n";
    } else if (args[1] == "memory" || args[1] == "mem") {
        std::cout << "Memory operations.\n"
                  << "Usage:\n"
                  << "    memory read <address> [size]     - Read memory at address (default size: 32 bytes)\n"
                  << "    memory write <address> <data>    - Write data to memory\n"
                  << "Examples:\n"
                  << "    memory read 0x555555555156\n"
                  << "    memory read 0x555555555156 16\n"
                  << "    memory write 0x555555555156 [0xff,0xaa,0x11]\n";
    } else if (args[1] == "register" || args[1] == "reg") {
        std::cout << "Usage:\n"
                  << "    register read\n"
                  << "    register read <register>\n"
                  << "    register read all\n"
                  << "    register write <register> <value>\n";
    } else if (args[1] == "stepi" || args[1] == "si") {
        std::cout << "Single step an instruction\n";
    } else {
        std::cerr << "Unknown command: " << args[1] << '\n';
    }
}

// Helper function for print_help calls with initializer list
void print_help_init(std::initializer_list<std::string> args_list) {
    std::vector<std::string> args_vec(args_list);
    print_help(std::span<const std::string>(args_vec));
}

}  // namespace xdb_handlers

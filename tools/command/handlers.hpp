#pragma once

#include <libxdb/process.hpp>
#include <span>
#include <string>

namespace xdb_handlers {

// Help command handlers
void print_help(std::span<const std::string> args);
void print_help_init(std::initializer_list<std::string> args_list);

// Breakpoint command handlers
void handle_breakpoint_command(xdb::process &process, std::span<const std::string> args);

// Watchpoint command handlers
void handle_watchpoint_command(xdb::process &process, std::span<const std::string> args);

// Register command handlers
void handle_register_command(xdb::process &process, std::span<const std::string> args);

// Memory command handlers
void handle_memory_command(xdb::process &process, std::span<const std::string> args);

// Disassemble command handlers
void handle_disassemble_command(xdb::process &process, std::span<const std::string> args);
void print_disassembly(xdb::process &process, xdb::virt_addr address, std::size_t n_instructions);

}  // namespace xdb_handlers

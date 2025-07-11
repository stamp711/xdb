#include <signal.h>

#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>
#include <libxdb/bit.hpp>
#include <libxdb/error.hpp>
#include <libxdb/pipe.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <string>

namespace {

bool kill_process(pid_t pid) { return kill(pid, SIGKILL) == 0; }

char get_process_status(pid_t pid) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string data;
    std::getline(stat, data);
    // 1 (systemd) S ...
    //             ^
    return data[data.rfind(')') + 2];
}

std::filesystem::path test_path() {
    char exe_path[1024];
    ssize_t count = readlink("/proc/self/exe", exe_path, sizeof(exe_path));
    if (count == -1) {
        throw std::runtime_error("Failed to read /proc/self/exe");
    }
    return std::filesystem::path(exe_path).parent_path();
}

}  // namespace

TEST_CASE("process::launch success", "[process]") {
    auto proc = xdb::process::launch("/bin/sleep");
    REQUIRE(get_process_status(proc->pid()) == 't');
    REQUIRE(kill_process(proc->pid()));
}

TEST_CASE("process::launch failure", "[process]") {
    REQUIRE_THROWS_AS(xdb::process::launch(test_path() / "/bin/doesnotexist"),
                      xdb::error);
}

TEST_CASE("process::attach success", "[process]") {
    auto launched =
        xdb::process::launch(test_path() / "targets/run_endlessly", false);
    auto attached = xdb::process::attach(launched->pid());
    REQUIRE(get_process_status(launched->pid()) == 't');
}

TEST_CASE("process::attach invalid PID", "[process]") {
    REQUIRE_THROWS_AS(xdb::process::attach(0), xdb::error);
}

TEST_CASE("process::resume success", "[process]") {
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    proc->resume();
    REQUIRE(get_process_status(proc->pid()) == 'R');
}

TEST_CASE("process::resume already terminated", "[process]") {
    auto proc = xdb::process::launch(test_path() / "targets/end_immediately");
    proc->resume();
    proc->wait_on_signal();
    REQUIRE_THROWS_AS(proc->resume(), xdb::error);
}

TEST_CASE("Write register works", "[register]") {
    xdb::pipe channel(false);

    auto proc = xdb::process::launch(test_path() / "targets/reg_write", true,
                                     channel.get_write());
    channel.close_write();

    // Wait for the process to trap itself
    proc->resume();
    proc->wait_on_signal();

    // GPR rsi
    auto& regs = proc->get_registers();
    regs.write_by_id(xdb::register_id::rsi, 0xdeadbeef);
    proc->resume();
    proc->wait_on_signal();
    auto output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "0xdeadbeef");

    // MMX mm0
    regs.write_by_id(xdb::register_id::mm0, 0xba5eba11);
    proc->resume();
    proc->wait_on_signal();
    output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "0xba5eba11");

    // SSE xmm0
    regs.write_by_id(xdb::register_id::xmm0, 42.24);
    proc->resume();
    proc->wait_on_signal();
    output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "42.24");

    // x87 st0
    regs.write_by_id(xdb::register_id::st0, 12.21L);
    regs.write_by_id(
        xdb::register_id::fsw,
        std::uint16_t{
            0b0011100000000000});  // bits 11-13 track top of the stack
    regs.write_by_id(
        xdb::register_id::ftw,
        std::uint16_t{0b0011111111111111});  // 00 means valid, 11 means empty
    proc->resume();
    proc->wait_on_signal();
    output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "12.21");
}

#include <elf.h>
#include <signal.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <libxdb/bit.hpp>
#include <libxdb/error.hpp>
#include <libxdb/pipe.hpp>
#include <libxdb/process.hpp>
#include <libxdb/register_info.hpp>
#include <libxdb/types.hpp>
#include <regex>
#include <string>

namespace {

std::string_view to_string_view(const std::vector<std::byte>& vec) {
    return std::string_view(reinterpret_cast<const char*>(vec.data()),
                            vec.size());
}

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

std::uint64_t get_elf_file_offset_of_address(std::filesystem::path path,
                                             std::uint64_t file_address) {
    std::string command = "readelf -WS " + path.string();
    auto pipe = ::popen(command.c_str(), "r");

    // Type            Address          Off    Size
    // PROGBITS        0000000000001040 001040 000113
    std::regex regex(R"(PROGBITS\s+(\w+)\s+(\w+)\s+(\w+))");

    char* line = nullptr;
    std::size_t len = 0;
    while (::getline(&line, &len, pipe)) {
        std::cmatch match;
        if (std::regex_search(line, match, regex)) {
            auto address = std::stoull(match[1], nullptr, 16);
            auto offset = std::stoull(match[2], nullptr, 16);
            auto size = std::stoull(match[3], nullptr, 16);
            if (file_address >= address && file_address < (address + size)) {
                ::free(line);
                ::pclose(pipe);
                return file_address - address + offset;
            }
        }
        ::free(line);
        line = nullptr;
    }

    pclose(pipe);
    xdb::error::send("Could not find section load bias");
}

std::uint64_t get_entry_point_offset(std::filesystem::path path) {
    std::ifstream elf_file(path);

    Elf64_Ehdr ehdr;
    elf_file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));

    auto entry_file_address = ehdr.e_entry;
    return get_elf_file_offset_of_address(path, entry_file_address);
}

xdb::virt_addr get_load_address(pid_t pid, std::uint64_t offset_in_file) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");

    // 555555555000-555555556000 r-xp 00001000 08:02 5280459
    // /xxx/xdb/build/test/targets/reg_read
    // TODO: verify file name, because things like ld-linux.so can also
    // appear in the maps file.
    std::regex regex(R"((\w+)-\w+ ..(.). (\w+))");

    std::string line;
    while (std::getline(maps, line)) {
        std::smatch match;
        if (std::regex_search(line, match, regex)) {
            auto start_addr = std::stoull(match[1], nullptr, 16);
            auto perm_char = match[2].str()[0];
            auto file_offset = std::stoull(match[3], nullptr, 16);
            if (perm_char == 'x') {
                // This is the first executable mapping
                return xdb::virt_addr(start_addr +
                                      (offset_in_file - file_offset));
            }
        }
    }
    xdb::error::send("Could not find load address");
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

TEST_CASE("Write registers", "[register]") {
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

TEST_CASE("Read registers", "[register]") {
    auto proc = xdb::process::launch(test_path() / "targets/reg_read");
    auto& regs = proc->get_registers();

    // r13
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint64_t>(xdb::register_id::r13) ==
            0xdeadbeefcafebabe);

    // r13d
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint32_t>(xdb::register_id::r13d) ==
            0xabcdef01);

    // r13w
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint16_t>(xdb::register_id::r13w) ==
            0x1234);

    // r13b
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint8_t>(xdb::register_id::r13b) == 42);

    // ah
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint8_t>(xdb::register_id::ah) == 41);

    // mm0
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<xdb::byte64>(xdb::register_id::mm0) ==
            xdb::to_byte64(0xba5eba11));

    // xmm0
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<xdb::byte128>(xdb::register_id::xmm0) ==
            xdb::to_byte128(42.25));

    // st0
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<long double>(xdb::register_id::st0) == 42.25L);
}

TEST_CASE("Create breakpoint site", "[breakpoint]") {
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    auto& bp = proc->create_breakpoint_site(xdb::virt_addr(42));
    REQUIRE(bp.address().addr() == 42);
}

TEST_CASE("Breakpoint sites have unique ids", "[breakpoint]") {
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    auto& bp1 = proc->create_breakpoint_site(xdb::virt_addr(42));
    auto& bp2 = proc->create_breakpoint_site(xdb::virt_addr(43));
    auto& bp3 = proc->create_breakpoint_site(xdb::virt_addr(44));
    REQUIRE(bp1.id() != bp2.id());
    REQUIRE(bp2.id() != bp3.id());
    REQUIRE(bp1.id() != bp3.id());
}

TEST_CASE("Breakpoint site lookup", "[breakpoint]") {
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    const auto* cproc = proc.get();
    auto& cbps = cproc->breakpoint_sites();

    auto va1 = xdb::virt_addr(42);
    auto va2 = xdb::virt_addr(43);
    auto va3 = xdb::virt_addr(44);

    auto id1 = proc->create_breakpoint_site(va1).id();
    auto id2 = proc->create_breakpoint_site(va2).id();
    auto id3 = proc->create_breakpoint_site(va3).id();

    REQUIRE(cbps.contains_id(id1));
    REQUIRE(cbps.contains_address(va1));
    REQUIRE(cbps.get_by_id(id1).address() == va1);
    REQUIRE(cbps.get_by_address(va1).address() == va1);

    REQUIRE(cbps.contains_id(id2));
    REQUIRE(cbps.contains_address(va2));
    REQUIRE(cbps.get_by_id(id2).address() == va2);
    REQUIRE(cbps.get_by_address(va2).address() == va2);

    REQUIRE(cbps.contains_id(id3));
    REQUIRE(cbps.contains_address(va3));
    REQUIRE(cbps.get_by_id(id3).address() == va3);
    REQUIRE(cbps.get_by_address(va3).address() == va3);

    REQUIRE_THROWS_AS(cbps.get_by_address(xdb::virt_addr(99)), xdb::error);
    REQUIRE_THROWS_AS(cbps.get_by_id(999), xdb::error);
}

TEST_CASE("Breakpoint site list size", "[breakpoint]") {
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    const auto& cbps = proc->breakpoint_sites();

    REQUIRE(cbps.empty());
    REQUIRE(cbps.size() == 0);

    proc->create_breakpoint_site(xdb::virt_addr(42));
    REQUIRE(!cbps.empty());
    REQUIRE(cbps.size() == 1);

    proc->create_breakpoint_site(xdb::virt_addr(43));
    REQUIRE(!cbps.empty());
    REQUIRE(cbps.size() == 2);

    proc->create_breakpoint_site(xdb::virt_addr(44));
    REQUIRE(!cbps.empty());
    REQUIRE(cbps.size() == 3);
}

TEST_CASE("Breakpoint sites iteration", "[breakpoint]") {
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    const auto& cbps = proc->breakpoint_sites();

    std::uint64_t addr = 42;
    for (auto i = 0; i < 99; ++i) {
        proc->create_breakpoint_site(xdb::virt_addr(addr++));
    }

    cbps.for_each([addr = std::uint64_t(42)](auto& bp) mutable {
        REQUIRE(bp.address().addr() == addr++);
    });
}

TEST_CASE("Set breakpoint on entry point", "[breakpoint]") {
    bool close_on_exec = false;
    xdb::pipe channel(close_on_exec);

    auto proc = xdb::process::launch(test_path() / "targets/hello", true,
                                     channel.get_write());
    channel.close_write();

    auto entrypoint_offset =
        get_entry_point_offset(test_path() / "targets/hello");
    auto entrypoint_va = get_load_address(proc->pid(), entrypoint_offset);

    proc->create_breakpoint_site(entrypoint_va).enable();
    proc->resume();
    auto reason = proc->wait_on_signal();

    // The process should have stopped at the breakpoint
    REQUIRE(reason.state == xdb::process_state::stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(proc->get_pc() == entrypoint_va);

    proc->resume();
    reason = proc->wait_on_signal();

    // The process should have exited after printing "hello"
    REQUIRE(reason.state == xdb::process_state::exited);
    REQUIRE(reason.info == 0);

    auto data = channel.read();
    REQUIRE(to_string_view(data) == "hello");
}

TEST_CASE("Remove breakpoint site", "[breakpoint]") {
    auto proc = xdb::process::launch(test_path() / "targets/end_immediately");

    auto entrypoint_offset =
        get_entry_point_offset(test_path() / "targets/hello");
    auto entrypoint_va = get_load_address(proc->pid(), entrypoint_offset);

    // Add breakpoint and remove by id
    {
        auto& bp = proc->create_breakpoint_site(entrypoint_va);
        bp.enable();

        REQUIRE(proc->breakpoint_sites().size() == 1);

        proc->breakpoint_sites().remove_by_id(bp.id());
        REQUIRE(proc->breakpoint_sites().empty());
    }

    // Add breakpoint and remove by address
    {
        auto& bp = proc->create_breakpoint_site(entrypoint_va);
        bp.enable();

        REQUIRE(proc->breakpoint_sites().size() == 1);

        proc->breakpoint_sites().remove_by_address(entrypoint_va);
        REQUIRE(proc->breakpoint_sites().empty());
    }

    proc->resume();
    auto reason = proc->wait_on_signal();

    // All breakpoints removed, the process should have exited immediately
    REQUIRE(reason.state == xdb::process_state::exited);
    REQUIRE(reason.info == 0);
}

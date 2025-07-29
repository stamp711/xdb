#include <elf.h>
#include <fmt/base.h>
#include <sys/signal.h>

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
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
#include <memory>
#include <regex>
#include <string>

namespace {

std::string_view to_string_view(const std::vector<std::byte>& vec) {
    return {reinterpret_cast<const char*>(vec.data()), vec.size()};
}

bool kill_process(pid_t pid) { return ::kill(pid, SIGKILL) == 0; }

char get_process_status(pid_t pid) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string data;
    std::getline(stat, data);
    // 1 (systemd) S ...
    //             ^
    return data[data.rfind(')') + 2];
}

std::filesystem::path test_path() {
    constexpr std::size_t MAX_PATH_LENGTH = 1024;
    std::array<char, MAX_PATH_LENGTH> exe_path{};
    ssize_t count = readlink("/proc/self/exe", exe_path.data(), exe_path.size());
    if (count == -1) {
        throw std::runtime_error("Failed to read /proc/self/exe");
    }
    return std::filesystem::path(exe_path.data()).parent_path();
}

std::uint64_t get_elf_file_offset_of_address(const std::filesystem::path& path, std::uint64_t file_address) {
    std::string command = "readelf -WS " + path.string();
    auto* pipe = ::popen(command.c_str(), "r");
    if (pipe == nullptr) xdb::error::send_errno("popen errir");

    // Auto close pipe
    auto pipe_guard = std::unique_ptr<FILE, std::function<void(FILE*)>>(pipe, [](FILE* p) { ::pclose(p); });

    // Type            Address          Off    Size
    // PROGBITS        0000000000001040 001040 000113
    std::regex regex(R"(PROGBITS\s+(\w+)\s+(\w+)\s+(\w+))");
    constexpr int HEX_BASE = 16;

    char* line = nullptr;
    std::size_t len = 0;

    // Auto free line
    std::unique_ptr<void, std::function<void(void*)>> line_guard(nullptr, [&line](void*) {
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory)
        ::free(line);
    });

    // getline will realloc() if needed
    while (::getline(&line, &len, pipe) > 0) {
        std::cmatch match;
        if (std::regex_search(line, match, regex)) {
            auto address = std::stoull(match[1], nullptr, HEX_BASE);
            auto offset = std::stoull(match[2], nullptr, HEX_BASE);
            auto size = std::stoull(match[3], nullptr, HEX_BASE);
            if (file_address >= address && file_address < (address + size)) {
                return file_address - address + offset;
            }
        }
    }

    xdb::error::send("Could not find section load bias");
}

std::uint64_t get_entry_point_offset(const std::filesystem::path& path) {
    std::ifstream elf_file(path);

    Elf64_Ehdr ehdr;
    elf_file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));

    auto entry_file_address = ehdr.e_entry;
    return get_elf_file_offset_of_address(path, entry_file_address);
}

// Strong type for file offsets to avoid parameter confusion
struct file_offset {
    std::uint64_t value;
    explicit file_offset(std::uint64_t val) : value(val) {}
};

xdb::virt_addr get_load_address(pid_t pid, file_offset offset_in_file) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");

    // 555555555000-555555556000 r-xp 00001000 08:02 5280459
    // /xxx/xdb/build/test/targets/reg_read
    // TODO: verify file name, because things like ld-linux.so can also
    // appear in the maps file.
    std::regex regex(R"((\w+)-\w+ ..(.). (\w+))");

    constexpr int HEX_BASE = 16;
    std::string line;
    while (std::getline(maps, line)) {
        std::smatch match;
        if (std::regex_search(line, match, regex)) {
            auto start_addr = std::stoull(match[1], nullptr, HEX_BASE);
            auto perm_char = match[2].str()[0];
            auto file_offset = std::stoull(match[3], nullptr, HEX_BASE);
            if (perm_char == 'x') {
                // This is the first executable mapping
                return xdb::virt_addr(start_addr + (offset_in_file.value - file_offset));
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
    REQUIRE_THROWS_AS(xdb::process::launch(test_path() / "/bin/doesnotexist"), xdb::error);
}

TEST_CASE("process::attach success", "[process]") {
    auto launched = xdb::process::launch(test_path() / "targets/run_endlessly", false);
    auto attached = xdb::process::attach(launched->pid());
    REQUIRE(get_process_status(launched->pid()) == 't');
}

TEST_CASE("process::attach invalid PID", "[process]") { REQUIRE_THROWS_AS(xdb::process::attach(0), xdb::error); }

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

    auto proc = xdb::process::launch(test_path() / "targets/reg_write", true, channel.get_write());
    channel.close_write();

    // Wait for the process to trap itself
    proc->resume();
    proc->wait_on_signal();

    auto& regs = proc->get_registers();

    // GPR rsi
    constexpr std::uint64_t rsi_test_value = 0xdeadbeef;
    regs.write_by_id(xdb::register_id::rsi, rsi_test_value);
    proc->resume();
    proc->wait_on_signal();
    auto output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "0xdeadbeef");

    // MMX mm0
    constexpr std::uint64_t mm0_test_value = 0xba5eba11;
    regs.write_by_id(xdb::register_id::mm0, mm0_test_value);
    proc->resume();
    proc->wait_on_signal();
    output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "0xba5eba11");

    // SSE xmm0
    constexpr double xmm0_test_value = 42.24;
    regs.write_by_id(xdb::register_id::xmm0, xmm0_test_value);
    proc->resume();
    proc->wait_on_signal();
    output = channel.read();
    REQUIRE(xdb::to_string_view(output) == "42.24");

    // x87 st0
    constexpr long double st0_test_value = 12.21L;
    constexpr std::uint16_t fsw_value = 0b0011100000000000;  // bits 11-13 track top of the stack
    constexpr std::uint16_t ftw_value = 0b0011111111111111;  // 00 means valid, 11 means empty
    regs.write_by_id(xdb::register_id::st0, st0_test_value);
    regs.write_by_id(xdb::register_id::fsw, fsw_value);
    regs.write_by_id(xdb::register_id::ftw, ftw_value);
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
    REQUIRE(regs.read_by_id_as<std::uint64_t>(xdb::register_id::r13) == 0xdeadbeefcafebabe);

    // r13d
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint32_t>(xdb::register_id::r13d) == 0xabcdef01);

    // r13w
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<std::uint16_t>(xdb::register_id::r13w) == 0x1234);

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
    REQUIRE(regs.read_by_id_as<xdb::byte64>(xdb::register_id::mm0) == xdb::to_byte64(0xba5eba11));

    // xmm0
    constexpr double expected_xmm0_value = 42.25;
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<xdb::byte128>(xdb::register_id::xmm0) == xdb::to_byte128(expected_xmm0_value));

    // st0
    constexpr long double expected_st0_value = 42.25L;
    proc->resume();
    proc->wait_on_signal();
    REQUIRE(regs.read_by_id_as<long double>(xdb::register_id::st0) == expected_st0_value);
}

TEST_CASE("Create breakpoint site", "[breakpoint]") {
    constexpr std::uint64_t test_address = 42;
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    auto& bp = proc->create_breakpoint_site(xdb::virt_addr(test_address));
    REQUIRE(bp.address().addr() == test_address);
}

TEST_CASE("Breakpoint sites have unique ids", "[breakpoint]") {
    constexpr std::uint64_t test_address_1 = 42;
    constexpr std::uint64_t test_address_2 = 43;
    constexpr std::uint64_t test_address_3 = 44;
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    auto& bp1 = proc->create_breakpoint_site(xdb::virt_addr(test_address_1));
    auto& bp2 = proc->create_breakpoint_site(xdb::virt_addr(test_address_2));
    auto& bp3 = proc->create_breakpoint_site(xdb::virt_addr(test_address_3));
    REQUIRE(bp1.id() != bp2.id());
    REQUIRE(bp2.id() != bp3.id());
    REQUIRE(bp1.id() != bp3.id());
}

TEST_CASE("Breakpoint site lookup", "[breakpoint]") {
    constexpr std::uint64_t test_address_1 = 42;
    constexpr std::uint64_t test_address_2 = 43;
    constexpr std::uint64_t test_address_3 = 44;
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    const auto* cproc = proc.get();
    const auto& cbps = cproc->breakpoint_sites();

    auto va1 = xdb::virt_addr(test_address_1);
    auto va2 = xdb::virt_addr(test_address_2);
    auto va3 = xdb::virt_addr(test_address_3);

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
    constexpr std::uint64_t test_address_1 = 42;
    constexpr std::uint64_t test_address_2 = 43;
    constexpr std::uint64_t test_address_3 = 44;
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    const auto& cbps = proc->breakpoint_sites();

    REQUIRE(cbps.empty());
    REQUIRE(cbps.size() == 0);

    proc->create_breakpoint_site(xdb::virt_addr(test_address_1));
    REQUIRE(!cbps.empty());
    REQUIRE(cbps.size() == 1);

    proc->create_breakpoint_site(xdb::virt_addr(test_address_2));
    REQUIRE(!cbps.empty());
    REQUIRE(cbps.size() == 2);

    proc->create_breakpoint_site(xdb::virt_addr(test_address_3));
    REQUIRE(!cbps.empty());
    REQUIRE(cbps.size() == 3);
}

TEST_CASE("Breakpoint sites iteration", "[breakpoint]") {
    constexpr std::uint64_t start_address = 42;
    auto proc = xdb::process::launch(test_path() / "targets/run_endlessly");
    const auto& cbps = proc->breakpoint_sites();

    std::uint64_t addr = start_address;
    constexpr int num_breakpoints = 99;
    for (auto i = 0; i < num_breakpoints; ++i) {
        proc->create_breakpoint_site(xdb::virt_addr(addr++));
    }

    cbps.for_each([addr = start_address](auto& bp) mutable { REQUIRE(bp.address().addr() == addr++); });
}

TEST_CASE("Set breakpoint on entry point", "[breakpoint]") {
    bool close_on_exec = false;
    xdb::pipe channel(close_on_exec);

    auto proc = xdb::process::launch(test_path() / "targets/hello", true, channel.get_write());
    channel.close_write();

    auto entrypoint_offset = get_entry_point_offset(test_path() / "targets/hello");
    auto entrypoint_va = get_load_address(proc->pid(), file_offset(entrypoint_offset));

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

    auto entrypoint_offset = get_entry_point_offset(test_path() / "targets/hello");
    auto entrypoint_va = get_load_address(proc->pid(), file_offset(entrypoint_offset));

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

TEST_CASE("Reading and writing memory", "[memory]") {
    xdb::pipe channel(false);
    auto proc = xdb::process::launch(test_path() / "targets/memory", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    // Read address of variable 'a' and verify its value
    auto addr_data = channel.read();
    auto a_address = *reinterpret_cast<const std::uint64_t*>(addr_data.data());
    auto a_value = proc->read_memory_as<std::uint64_t>(xdb::virt_addr(a_address));
    REQUIRE(a_value == 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    // Read address of buffer 'b' and write test data to it
    static constexpr std::string test_str = "test";
    addr_data = channel.read();
    auto b_address = *reinterpret_cast<const std::uint64_t*>(addr_data.data());
    proc->write_memory(xdb::virt_addr(b_address),
                       {reinterpret_cast<const std::byte*>(test_str.c_str()), test_str.size() + 1});

    proc->resume();
    proc->wait_on_signal();

    // Verify output matches what we wrote
    auto output = channel.read();
    REQUIRE(to_string_view(output) == "test");
}

TEST_CASE("Hardware breakpoint evades memory checksums", "[breakpoint]") {
    bool close_on_exec = false;
    xdb::pipe channel(close_on_exec);
    auto proc = xdb::process::launch(test_path() / "targets/anti_debugger", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    auto func = xdb::virt_addr(xdb::from_bytes<std::uint64_t>(channel.read().data()));

    auto& soft = proc->create_breakpoint_site(func, false);
    soft.enable();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(to_string_view(channel.read()) == "Putting pepperoni on pizza...\n");

    proc->breakpoint_sites().remove_by_id(soft.id());
    auto& hard = proc->create_breakpoint_site(func, true);
    hard.enable();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(proc->get_pc() == func);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(to_string_view(channel.read()) == "Putting pineapple on pizza...\n");
}

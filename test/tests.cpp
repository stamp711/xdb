#include <signal.h>

#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <libxdb/error.hpp>
#include <libxdb/process.hpp>
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

}  // namespace

TEST_CASE("process::launch success", "[process]") {
    auto proc = xdb::process::launch("/bin/sleep");
    REQUIRE(get_process_status(proc->pid()) == 't');
    REQUIRE(kill_process(proc->pid()));
}

TEST_CASE("process::launch failure", "[process]") {
    REQUIRE_THROWS_AS(xdb::process::launch("/bin/doesnotexist"), xdb::error);
}

TEST_CASE("process::attach success", "[process]") {
    auto launched = xdb::process::launch("targets/run_endlessly", false);
    auto attached = xdb::process::attach(launched->pid());
    REQUIRE(get_process_status(launched->pid()) == 't');
}

TEST_CASE("process::attach invalid PID", "[process]") {
    REQUIRE_THROWS_AS(xdb::process::attach(0), xdb::error);
}

TEST_CASE("process::resume success", "[process]") {
    auto proc = xdb::process::launch("targets/run_endlessly");
    proc->resume();
    REQUIRE(get_process_status(proc->pid()) == 'R');
}

TEST_CASE("process::resume already terminated", "[process]") {
    auto proc = xdb::process::launch("targets/end_immediately");
    proc->resume();
    proc->wait_on_signal();
    REQUIRE_THROWS_AS(proc->resume(), xdb::error);
}

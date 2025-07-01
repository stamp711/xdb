#include <signal.h>

#include <catch2/catch_test_macros.hpp>
#include <libxdb/error.hpp>
#include <libxdb/process.hpp>

namespace {
bool kill_process(pid_t pid) { return kill(pid, SIGKILL) == 0; }
}  // namespace

TEST_CASE("process::launch success", "[process]") {
    auto proc = xdb::process::launch("/bin/sleep");
    REQUIRE(kill_process(proc->pid()));
}

TEST_CASE("process::launch failure", "[process]") {
    REQUIRE_THROWS_AS(xdb::process::launch("/bin/doesnotexist"), xdb::error);
}
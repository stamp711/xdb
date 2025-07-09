#include <fcntl.h>
#include <unistd.h>

#include <cstddef>
#include <libxdb/error.hpp>
#include <libxdb/pipe.hpp>
#include <vector>

namespace xdb {

pipe::pipe(bool close_on_exec) {
    if (::pipe2(fds_, close_on_exec ? O_CLOEXEC : 0) == -1) {
        error::send_errno("Pipe creation failed");
    }
}

pipe::~pipe() {
    close_read();
    close_write();
}

void pipe::close_read() {
    if (fds_[READ_END] != -1) {
        ::close(fds_[READ_END]);
        fds_[READ_END] = -1;
    }
}

void pipe::close_write() {
    if (fds_[WRITE_END] != -1) {
        ::close(fds_[WRITE_END]);
        fds_[WRITE_END] = -1;
    }
}

std::vector<std::byte> pipe::read() {
    if (fds_[READ_END] == -1) {
        error::send("Read end of pipe is closed");
    }
    std::byte buffer[1024];
    ssize_t bytes_read = ::read(fds_[READ_END], buffer, sizeof(buffer));
    if (bytes_read < 0) {
        error::send_errno("Read from pipe failed");
    }
    return std::vector<std::byte>(buffer, buffer + bytes_read);
}

void pipe::write(const std::byte* buf, size_t size) {
    if (fds_[WRITE_END] == -1) {
        error::send("Write end of pipe is closed");
    }
    ssize_t bytes_written = ::write(fds_[WRITE_END], buf, size);
    if (bytes_written < 0) {
        error::send_errno("Write to pipe failed");
    } else if (static_cast<size_t>(bytes_written) != size) {
        error::send("Partial write to pipe");
    }
}

}  // namespace xdb

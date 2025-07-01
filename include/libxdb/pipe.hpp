#pragma once

#include <cstddef>
#include <vector>
namespace xdb {

class pipe {
   public:
    explicit pipe(bool close_on_exec);
    ~pipe();

    int get_read() const { return fds_[READ_END]; }
    int get_write() const { return fds_[WRITE_END]; }
    int release_read();
    int release_write();
    void close_read();
    void close_write();

    std::vector<std::byte> read();
    void write(const std::byte* buf, size_t size);

   private:
    static const int READ_END = 0;
    static const int WRITE_END = 1;

    int fds_[2];
};

}  // namespace xdb
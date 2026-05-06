#pragma once
#include <unistd.h>

namespace neuro_mesh {

class UniqueFD {
    int m_fd;
public:
    UniqueFD() : m_fd(-1) {}
    explicit UniqueFD(int fd) : m_fd(fd) {}
    ~UniqueFD() { if (m_fd >= 0) ::close(m_fd); }

    UniqueFD(const UniqueFD&) = delete;
    UniqueFD& operator=(const UniqueFD&) = delete;
    UniqueFD(UniqueFD&& other) noexcept : m_fd(other.m_fd) { other.m_fd = -1; }
    UniqueFD& operator=(UniqueFD&& other) noexcept {
        if (this != &other) { if (m_fd >= 0) ::close(m_fd); m_fd = other.m_fd; other.m_fd = -1; }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return m_fd; }
    [[nodiscard]] bool valid() const noexcept { return m_fd >= 0; }

    int release() noexcept { int fd = m_fd; m_fd = -1; return fd; }
};

} // namespace neuro_mesh

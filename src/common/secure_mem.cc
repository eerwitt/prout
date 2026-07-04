#include "common/secure_mem.h"

#include <cstdlib>
#include <cstring>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace prout {

const std::uint8_t SecureBuffer::kEmpty[1] = {0};

void SecureZero(void *p, std::size_t n) {
  if (p == nullptr || n == 0)
    return;
#if defined(_WIN32)
  ::SecureZeroMemory(p, n);
#else
  // volatile store loop the optimizer is not allowed to drop.
  volatile std::uint8_t *v = static_cast<volatile std::uint8_t *>(p);
  while (n--)
    *v++ = 0;
#endif
}

void SecureBuffer::lock_pages() {
  if (data_ == nullptr || cap_ == 0)
    return;
#if defined(_WIN32)
  ::VirtualLock(data_, cap_);
#else
  ::mlock(data_, cap_);
#endif
}

void SecureBuffer::unlock_pages() {
  if (data_ == nullptr || cap_ == 0)
    return;
#if defined(_WIN32)
  ::VirtualUnlock(data_, cap_);
#else
  ::munlock(data_, cap_);
#endif
}

void SecureBuffer::resize(std::size_t n) {
  if (n + 1 <= cap_) {
    size_ = n;
    if (data_)
      data_[size_] = 0;
    return;
  }
  clear();
  cap_ = n + 1; // +1 for the NUL guard
  data_ = static_cast<std::uint8_t *>(std::malloc(cap_));
  if (data_ == nullptr) {
    cap_ = 0;
    size_ = 0;
    return;
  }
  lock_pages();
  size_ = n;
  std::memset(data_, 0, cap_);
}

void SecureBuffer::assign(const void *data, std::size_t n) {
  resize(n);
  if (data_ != nullptr && data != nullptr && n > 0) {
    std::memcpy(data_, data, n);
    data_[n] = 0;
  }
}

void SecureBuffer::clear() {
  if (data_ != nullptr) {
    SecureZero(data_, cap_);
    unlock_pages();
    std::free(data_);
    data_ = nullptr;
  }
  size_ = 0;
  cap_ = 0;
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&o) noexcept {
  if (this != &o) {
    clear();
    data_ = std::exchange(o.data_, nullptr);
    size_ = std::exchange(o.size_, 0);
    cap_ = std::exchange(o.cap_, 0);
  }
  return *this;
}

} // namespace prout

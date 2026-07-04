// Secure memory helpers for material that must never reach swap or linger in
// freed heap pages. Backed by VirtualLock() on Windows and mlock() on POSIX --
// both paths exist per the project's memory-locking invariant.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace prout {

// Overwrites `n` bytes at `p` with zeros in a way the compiler may not elide.
void SecureZero(void *p, std::size_t n);

// A byte buffer whose backing pages are locked into RAM (best-effort) and
// zeroized on destruction. Move-only. Use for decrypted credentials and keys.
class SecureBuffer {
public:
  SecureBuffer() = default;
  explicit SecureBuffer(std::size_t n) { resize(n); }
  ~SecureBuffer() { clear(); }

  SecureBuffer(SecureBuffer &&o) noexcept { *this = std::move(o); }
  SecureBuffer &operator=(SecureBuffer &&o) noexcept;
  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;

  void resize(std::size_t n);
  void assign(const void *data, std::size_t n);
  // Copies from a std::string, then wipes nothing (caller owns the source).
  void assign(const std::string &s) { assign(s.data(), s.size()); }
  void clear();

  std::uint8_t *data() { return data_; }
  const std::uint8_t *data() const { return data_; }
  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

  // View as a C string for injection into an environment block. The buffer is
  // kept NUL-terminated past `size()` so this is always valid.
  const char *c_str() const {
    return reinterpret_cast<const char *>(data_ ? data_ : kEmpty);
  }

private:
  static const std::uint8_t kEmpty[1];
  void lock_pages();
  void unlock_pages();

  std::uint8_t *data_ = nullptr; // capacity is size_+1 (NUL guard)
  std::size_t size_ = 0;
  std::size_t cap_ = 0;
};

} // namespace prout

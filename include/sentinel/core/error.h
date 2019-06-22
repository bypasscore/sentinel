#ifndef SENTINEL_CORE_ERROR_H
#define SENTINEL_CORE_ERROR_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SENTINEL_OK                          0
#define SENTINEL_ERROR_GENERIC              -1
#define SENTINEL_ERROR_INVALID_PARAMETER    -2
#define SENTINEL_ERROR_OUT_OF_MEMORY        -3
#define SENTINEL_ERROR_ACCESS_DENIED        -4
#define SENTINEL_ERROR_NOT_FOUND            -5
#define SENTINEL_ERROR_ALREADY_EXISTS       -6
#define SENTINEL_ERROR_ALREADY_INITIALIZED  -7
#define SENTINEL_ERROR_NOT_INITIALIZED      -8
#define SENTINEL_ERROR_TIMEOUT              -9
#define SENTINEL_ERROR_BUFFER_TOO_SMALL     -10
#define SENTINEL_ERROR_UNSUPPORTED          -11
#define SENTINEL_ERROR_IO                   -12
#define SENTINEL_ERROR_DRIVER_LOAD_FAILED   -13
#define SENTINEL_ERROR_DRIVER_COMM_FAILED   -14
#define SENTINEL_ERROR_PROCESS_NOT_FOUND    -15
#define SENTINEL_ERROR_MODULE_NOT_FOUND     -16
#define SENTINEL_ERROR_PATTERN_INVALID      -17
#define SENTINEL_ERROR_SIGNATURE_MISMATCH   -18
#define SENTINEL_ERROR_INTEGRITY_VIOLATION  -19
#define SENTINEL_ERROR_HOOK_DETECTED        -20
#define SENTINEL_ERROR_VBS_ENABLED          -21

const char* sentinel_error_string(int error_code);
u32 sentinel_last_os_error(void);

#ifdef __cplusplus
}

#include <string>
#include <optional>

namespace sentinel {

class Error {
public:
    Error() : code_(SENTINEL_OK) {}
    explicit Error(int code) : code_(code) {}
    Error(int code, const std::string& message) : code_(code), message_(message) {}

    bool ok() const { return code_ == SENTINEL_OK; }
    int code() const { return code_; }
    const std::string& message() const { return message_; }
    explicit operator bool() const { return !ok(); }

    static Error success() { return Error(); }
    static Error from_win32(unsigned long win32_error);
    static Error from_ntstatus(long ntstatus);
    const char* to_string() const;

private:
    int code_;
    std::string message_;
};

template<typename T>
class Result {
public:
    Result(const T& value) : value_(value), error_(SENTINEL_OK) {}
    Result(T&& value) : value_(std::move(value)), error_(SENTINEL_OK) {}
    Result(const Error& err) : error_(err) {}

    bool ok() const { return error_.ok(); }
    const T& value() const { return value_.value(); }
    T& value() { return value_.value(); }
    const Error& error() const { return error_; }

private:
    std::optional<T> value_;
    Error error_;
};

} // namespace sentinel
#endif

#endif

#pragma once

#include <stdexcept>
#include <string>
#include <variant>

namespace shieldtier {

struct Error {
    std::string message;
    std::string code;

    explicit Error(std::string msg, std::string c = "")
        : message(std::move(msg)), code(std::move(c)) {}
};

template <typename T>
class Result {
public:
    Result(T val) : storage_(std::move(val)) {}
    Result(Error err) : storage_(std::move(err)) {}

    bool ok() const { return std::holds_alternative<T>(storage_); }

    const T& value() const {
        if (!ok()) throw std::runtime_error("Result::value() called on error");
        return std::get<T>(storage_);
    }

    T& value() {
        if (!ok()) throw std::runtime_error("Result::value() called on error");
        return std::get<T>(storage_);
    }

    const Error& error() const {
        if (ok()) throw std::runtime_error("Result::error() called on ok value");
        return std::get<Error>(storage_);
    }

    // Transform the contained value if ok; pass error through unchanged.
    template <typename F>
    auto map(F&& f) const -> Result<decltype(f(std::declval<T>()))> {
        using U = decltype(f(std::declval<T>()));
        if (ok()) return Result<U>(f(value()));
        return Result<U>(error());
    }

private:
    std::variant<T, Error> storage_;
};

}  // namespace shieldtier

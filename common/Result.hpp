#pragma once
#include <variant>
#include <optional>
#include <string>
#include <stdexcept>
#include <utility>
#include <functional>

namespace neuro_mesh {

template<typename T, typename E = std::string>
class Result {
    std::variant<T, E> m_value;
public:
    Result(T val) : m_value(std::move(val)) {}
    Result(E err) : m_value(std::move(err)) {}

    [[nodiscard]] bool ok() const noexcept { return std::holds_alternative<T>(m_value); }
    [[nodiscard]] bool is_err() const noexcept { return !ok(); }

    [[nodiscard]] T& value() { return std::get<T>(m_value); }
    [[nodiscard]] const T& value() const { return std::get<T>(m_value); }
    [[nodiscard]] E& error() { return std::get<E>(m_value); }
    [[nodiscard]] const E& error() const { return std::get<E>(m_value); }

    [[nodiscard]] T& operator*() & { return value(); }
    [[nodiscard]] const T& operator*() const& { return value(); }
    [[nodiscard]] T&& operator*() && { return std::move(value()); }
    [[nodiscard]] T* operator->() { return &value(); }
    [[nodiscard]] const T* operator->() const { return &value(); }

    [[nodiscard]] T unwrap_or(T fallback) const {
        return ok() ? value() : std::move(fallback);
    }

    [[nodiscard]] T value_or(T fallback) const {
        return ok() ? value() : std::move(fallback);
    }

    template<typename F>
    [[nodiscard]] Result<std::invoke_result_t<F, const T&>, E> map(F&& f) const& {
        if (ok()) return std::invoke(std::forward<F>(f), value());
        return error();
    }

    template<typename F>
    [[nodiscard]] Result<std::invoke_result_t<F, const T&>, E> map(F&& f) && {
        if (ok()) return std::invoke(std::forward<F>(f), std::move(value()));
        return std::move(error());
    }

    template<typename F>
    [[nodiscard]] T map_or(T fallback, F&& f) const {
        return ok() ? std::invoke(std::forward<F>(f), value()) : std::move(fallback);
    }

    template<typename F>
    [[nodiscard]] Result<T, std::invoke_result_t<F, const E&>> map_err(F&& f) const& {
        if (ok()) return value();
        return std::invoke(std::forward<F>(f), error());
    }

    template<typename F>
    [[nodiscard]] Result<T, std::invoke_result_t<F, const E&>> map_err(F&& f) && {
        if (ok()) return std::move(value());
        return std::invoke(std::forward<F>(f), std::move(error()));
    }
};

template<typename E>
class Result<void, E> {
    std::optional<E> m_error;
public:
    Result() : m_error(std::nullopt) {}
    /* implicit */ Result(E err) : m_error(std::move(err)) {}

    [[nodiscard]] bool ok() const noexcept { return !m_error.has_value(); }
    [[nodiscard]] bool is_err() const noexcept { return m_error.has_value(); }
    [[nodiscard]] E& error() { return *m_error; }
    [[nodiscard]] const E& error() const { return *m_error; }
};

} // namespace neuro_mesh

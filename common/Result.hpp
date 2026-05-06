#pragma once
#include <variant>
#include <optional>
#include <string>

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

    [[nodiscard]] T unwrap_or(T fallback) const {
        return ok() ? value() : std::move(fallback);
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

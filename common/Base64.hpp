#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace neuro_mesh {

inline std::string base64_encode(const std::string& data) {
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    const auto* bytes = reinterpret_cast<const uint8_t*>(data.data());
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        out += chars[bytes[i] >> 2];
        out += chars[((bytes[i] & 0x03) << 4) | (bytes[i+1] >> 4)];
        out += chars[((bytes[i+1] & 0x0F) << 2) | (bytes[i+2] >> 6)];
        out += chars[bytes[i+2] & 0x3F];
    }
    if (i < data.size()) {
        out += chars[bytes[i] >> 2];
        if (i + 1 < data.size()) {
            out += chars[((bytes[i] & 0x03) << 4) | (bytes[i+1] >> 4)];
            out += chars[(bytes[i+1] & 0x0F) << 2];
        } else {
            out += chars[(bytes[i] & 0x03) << 4];
            out += '=';
        }
        out += '=';
    }
    return out;
}

enum class Base64Error { NONE, INVALID_CHAR, INVALID_LENGTH };

inline std::optional<std::string> base64_decode(const std::string& data, Base64Error* err_out = nullptr) {
    static const int8_t lookup[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    if (data.empty()) {
        if (err_out) *err_out = Base64Error::NONE;
        return std::string{};
    }

    if (data.size() % 4 != 0) {
        if (err_out) *err_out = Base64Error::INVALID_LENGTH;
        return std::nullopt;
    }

    std::string out;
    out.reserve((data.size() / 4) * 3);
    int val = 0, valb = -8;
    for (char c : data) {
        if (c == '=') break;
        if (static_cast<size_t>(c) >= 128 || lookup[static_cast<size_t>(c)] == -1) {
            if (err_out) *err_out = Base64Error::INVALID_CHAR;
            return std::nullopt;
        }
        val = (val << 6) + lookup[static_cast<size_t>(c)];
        valb += 6;
        if (valb >= 0) {
            out += static_cast<char>((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    if (err_out) *err_out = Base64Error::NONE;
    return out;
}

inline std::string base64_decode_legacy(const std::string& data) {
    auto result = base64_decode(data);
    return result.value_or(std::string{});
}

} // namespace neuro_mesh

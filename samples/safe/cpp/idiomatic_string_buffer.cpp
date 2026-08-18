// Mẫu code an toàn — dùng std::string/std::vector<char> thay vì buffer thô
// (C++ idiomatic), thay vì tự quản lý char[] + strcpy/strncpy như 2 sample
// còn lại. Vẫn có 1 điểm dùng memcpy() để mô phỏng serialize dữ liệu ra
// byte buffer — nhưng bound lấy từ chính std::vector::size(), không phải
// hằng số đoán mò, nên vẫn an toàn.

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

class RequestBuilder {
public:
    RequestBuilder &SetMethod(const std::string &method) {
        method_ = method;
        return *this;
    }

    RequestBuilder &SetPath(const std::string &path) {
        path_ = path;
        return *this;
    }

    RequestBuilder &AddHeader(const std::string &key, const std::string &value) {
        headers_.push_back(key + ": " + value);
        return *this;
    }

    // SAFE: dựng chuỗi bằng std::string/std::ostringstream, không có buffer
    // cố định kích thước nào cần lo overflow.
    std::string Build() const {
        std::ostringstream out;
        out << method_ << " " << path_ << " HTTP/1.1\r\n";
        for (const auto &header : headers_) {
            out << header << "\r\n";
        }
        out << "\r\n";
        return out.str();
    }

private:
    std::string method_ = "GET";
    std::string path_ = "/";
    std::vector<std::string> headers_;
};

// SAFE: memcpy vào std::vector<char> đã resize đúng bằng payload.size() —
// bound lấy từ chính kích thước nguồn/đích thật, không phải hằng số cố định
// nhỏ hơn dữ liệu cần copy.
std::vector<char> SerializePayload(const std::string &payload) {
    std::vector<char> buffer(payload.size());
    if (!payload.empty()) {
        memcpy(buffer.data(), payload.data(), payload.size());
    }
    return buffer;
}

}  // namespace

int main() {
    RequestBuilder builder;
    std::string request = builder.SetMethod("POST")
                               .SetPath("/api/v1/scan")
                               .AddHeader("Content-Type", "application/json")
                               .AddHeader("Accept", "application/json")
                               .Build();

    std::vector<char> serialized = SerializePayload(request);
    std::cout << "serialized " << serialized.size() << " bytes" << std::endl;

    return 0;
}

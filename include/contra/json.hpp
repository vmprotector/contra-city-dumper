#pragma once

#include "contra/model.hpp"

#include <filesystem>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace contra::emit {

class JsonWriter {
public:
    explicit JsonWriter(std::ostream& out) : out_(out) {}

    void beginObject();
    void endObject();
    void beginArray();
    void endArray();
    void key(std::string_view name);
    void string(std::string_view value);
    void number(std::int64_t value);
    void number(std::uint64_t value);
    void boolean(bool value);
    void null();

private:
    void separate();
    void newline();

    std::ostream& out_;
    int indent_ = 0;
    std::vector<bool> first_;
    bool afterKey_ = false;
};

void writeJson(const model::SdkModel& model, const std::filesystem::path& path);
void writeHpp(const model::SdkModel& model, const std::filesystem::path& path);

}  // namespace contra::emit

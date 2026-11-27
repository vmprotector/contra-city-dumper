#include "contra/json.hpp"

#include <iomanip>
#include <sstream>

namespace contra::emit {

namespace {

void writeEscaped(std::ostream& out, std::string_view value) {
    out << '"';
    for (unsigned char c : value) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
                break;
        }
    }
    out << '"';
}

}  // namespace

void JsonWriter::newline() {
    out_ << '\n' << std::string(static_cast<std::size_t>(indent_) * 2, ' ');
}

void JsonWriter::separate() {
    if (afterKey_) {
        afterKey_ = false;
        return;
    }
    if (!first_.empty()) {
        if (!first_.back()) {
            out_ << ',';
        }
        first_.back() = false;
        newline();
    }
}

void JsonWriter::beginObject() {
    separate();
    out_ << '{';
    first_.push_back(true);
    ++indent_;
}

void JsonWriter::endObject() {
    const bool empty = first_.back();
    --indent_;
    if (!empty) {
        newline();
    }
    out_ << '}';
    first_.pop_back();
    if (first_.empty()) {
        out_ << '\n';
    }
}

void JsonWriter::beginArray() {
    separate();
    out_ << '[';
    first_.push_back(true);
    ++indent_;
}

void JsonWriter::endArray() {
    const bool empty = first_.back();
    --indent_;
    if (!empty) {
        newline();
    }
    out_ << ']';
    first_.pop_back();
    if (first_.empty()) {
        out_ << '\n';
    }
}

void JsonWriter::key(std::string_view name) {
    separate();
    writeEscaped(out_, name);
    out_ << ": ";
    afterKey_ = true;
}

void JsonWriter::string(std::string_view value) {
    separate();
    writeEscaped(out_, sanitizeUtf8(value));
}

void JsonWriter::number(std::int64_t value) {
    separate();
    out_ << value;
}

void JsonWriter::number(std::uint64_t value) {
    separate();
    out_ << value;
}

void JsonWriter::boolean(bool value) {
    separate();
    out_ << (value ? "true" : "false");
}

void JsonWriter::null() {
    separate();
    out_ << "null";
}

}  // namespace contra::emit

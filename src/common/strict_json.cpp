#include "strict_json.h"

#include <QSet>
#include <QString>

#include <utility>

namespace tcp_chat::protocol::detail {
namespace {

    /// Parses strict JSON without building a document or accepting duplicate keys.
    class StrictJsonParser {
    public:
        /// Creates a parser over a valid UTF-8 byte sequence.
        explicit StrictJsonParser(QByteArrayView json)
            : json_(json)
        {
        }

        /// Parses one complete JSON value and rejects trailing non-whitespace bytes.
        bool parse();

    private:
        /// Parses a value within the configured nesting limit.
        bool parse_value(int depth);
        /// Parses an object and rejects duplicate decoded member names.
        bool parse_object(int depth);
        /// Parses an array and its comma separators.
        bool parse_array(int depth);
        /// Parses a JSON string and optionally returns its decoded value.
        bool parse_string(QString* decoded);
        /// Parses a four-digit Unicode escape and optionally appends it to a string.
        bool parse_unicode_escape(QString* decoded);
        /// Parses the JSON number grammar without extensions.
        bool parse_number();
        /// Consumes one exact literal string.
        bool consume_literal(QByteArrayView literal);
        /// Consumes one expected byte when present.
        bool consume(char expected);
        /// Skips only whitespace permitted by JSON.
        void skip_whitespace();
        /// Returns the expected UTF-8 sequence length, or zero for an invalid lead byte.
        qsizetype utf8_sequence_length(unsigned char lead) const;
        /// Returns a hexadecimal digit value, or -1 for a non-hexadecimal byte.
        int hex_value(char value) const;

        QByteArrayView json_;
        qsizetype position_ = 0;
    };

    bool StrictJsonParser::parse()
    {
        skip_whitespace();
        if (!parse_value(0)) {
            return false;
        }
        skip_whitespace();
        return position_ == json_.size();
    }

    bool StrictJsonParser::parse_value(int depth)
    {
        if (depth > maximum_json_depth || position_ >= json_.size()) {
            return false;
        }

        switch (json_[position_]) {
        case '{':
            return parse_object(depth);
        case '[':
            return parse_array(depth);
        case '"':
            return parse_string(nullptr);
        case 't':
            return consume_literal(QByteArrayView { "true" });
        case 'f':
            return consume_literal(QByteArrayView { "false" });
        case 'n':
            return consume_literal(QByteArrayView { "null" });
        default:
            return parse_number();
        }
    }

    bool StrictJsonParser::parse_object(int depth)
    {
        ++position_;
        skip_whitespace();

        QSet<QString> keys;
        if (consume('}')) {
            return true;
        }

        while (position_ < json_.size()) {
            QString key;
            if (!parse_string(&key) || keys.contains(key)) {
                return false;
            }
            keys.insert(key);

            skip_whitespace();
            if (!consume(':')) {
                return false;
            }
            skip_whitespace();
            if (!parse_value(depth + 1)) {
                return false;
            }
            skip_whitespace();

            if (consume('}')) {
                return true;
            }
            if (!consume(',')) {
                return false;
            }
            skip_whitespace();
        }

        return false;
    }

    bool StrictJsonParser::parse_array(int depth)
    {
        ++position_;
        skip_whitespace();
        if (consume(']')) {
            return true;
        }

        while (position_ < json_.size()) {
            if (!parse_value(depth + 1)) {
                return false;
            }
            skip_whitespace();
            if (consume(']')) {
                return true;
            }
            if (!consume(',')) {
                return false;
            }
            skip_whitespace();
        }

        return false;
    }

    bool StrictJsonParser::parse_string(QString* decoded)
    {
        if (!consume('"')) {
            return false;
        }

        QString result;
        while (position_ < json_.size()) {
            const unsigned char current = static_cast<unsigned char>(json_[position_]);
            if (current == '"') {
                ++position_;
                if (decoded != nullptr) {
                    *decoded = std::move(result);
                }
                return true;
            }
            if (current <= 0x1f) {
                return false;
            }

            if (current == '\\') {
                ++position_;
                if (position_ >= json_.size()) {
                    return false;
                }

                const char escape = json_[position_++];
                if (escape == 'u') {
                    if (!parse_unicode_escape(decoded != nullptr ? &result : nullptr)) {
                        return false;
                    }
                    continue;
                }

                QChar escaped;
                switch (escape) {
                case '"':
                    escaped = QChar::fromLatin1('"');
                    break;
                case '\\':
                    escaped = QChar::fromLatin1('\\');
                    break;
                case '/':
                    escaped = QChar::fromLatin1('/');
                    break;
                case 'b':
                    escaped = QChar::fromLatin1('\b');
                    break;
                case 'f':
                    escaped = QChar::fromLatin1('\f');
                    break;
                case 'n':
                    escaped = QChar::fromLatin1('\n');
                    break;
                case 'r':
                    escaped = QChar::fromLatin1('\r');
                    break;
                case 't':
                    escaped = QChar::fromLatin1('\t');
                    break;
                default:
                    return false;
                }
                if (decoded != nullptr) {
                    result.append(escaped);
                }
                continue;
            }

            const qsizetype length = utf8_sequence_length(current);
            if (length == 0 || position_ + length > json_.size()) {
                return false;
            }
            if (decoded != nullptr) {
                result.append(QString::fromUtf8(json_.sliced(position_, length)));
            }
            position_ += length;
        }

        return false;
    }

    bool StrictJsonParser::parse_unicode_escape(QString* decoded)
    {
        if (position_ + 4 > json_.size()) {
            return false;
        }

        quint16 value = 0;
        for (int digit = 0; digit < 4; ++digit) {
            const int nibble = hex_value(json_[position_++]);
            if (nibble < 0) {
                return false;
            }
            value = static_cast<quint16>((value << 4) | nibble);
        }

        if (decoded != nullptr) {
            decoded->append(QChar { static_cast<char16_t>(value) });
        }
        return true;
    }

    bool StrictJsonParser::parse_number()
    {
        consume('-');
        if (position_ >= json_.size()) {
            return false;
        }

        if (consume('0')) {
            if (position_ < json_.size() && json_[position_] >= '0' && json_[position_] <= '9') {
                return false;
            }
        } else {
            if (json_[position_] < '1' || json_[position_] > '9') {
                return false;
            }
            while (position_ < json_.size() && json_[position_] >= '0' && json_[position_] <= '9') {
                ++position_;
            }
        }

        if (consume('.')) {
            if (position_ >= json_.size() || json_[position_] < '0' || json_[position_] > '9') {
                return false;
            }
            while (position_ < json_.size() && json_[position_] >= '0' && json_[position_] <= '9') {
                ++position_;
            }
        }

        if (position_ < json_.size() && (json_[position_] == 'e' || json_[position_] == 'E')) {
            ++position_;
            if (position_ < json_.size() && (json_[position_] == '+' || json_[position_] == '-')) {
                ++position_;
            }
            if (position_ >= json_.size() || json_[position_] < '0' || json_[position_] > '9') {
                return false;
            }
            while (position_ < json_.size() && json_[position_] >= '0' && json_[position_] <= '9') {
                ++position_;
            }
        }

        return true;
    }

    bool StrictJsonParser::consume_literal(QByteArrayView literal)
    {
        if (position_ + literal.size() > json_.size()
            || json_.sliced(position_, literal.size()) != literal) {
            return false;
        }

        position_ += literal.size();
        return true;
    }

    bool StrictJsonParser::consume(char expected)
    {
        if (position_ >= json_.size() || json_[position_] != expected) {
            return false;
        }

        ++position_;
        return true;
    }

    void StrictJsonParser::skip_whitespace()
    {
        while (position_ < json_.size()) {
            const char current = json_[position_];
            if (current != ' ' && current != '\t' && current != '\n' && current != '\r') {
                return;
            }
            ++position_;
        }
    }

    qsizetype StrictJsonParser::utf8_sequence_length(unsigned char lead) const
    {
        if (lead <= 0x7f) {
            return 1;
        }
        if (lead >= 0xc2 && lead <= 0xdf) {
            return 2;
        }
        if (lead >= 0xe0 && lead <= 0xef) {
            return 3;
        }
        if (lead >= 0xf0 && lead <= 0xf4) {
            return 4;
        }
        return 0;
    }

    int StrictJsonParser::hex_value(char value) const
    {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
            return 10 + value - 'a';
        }
        if (value >= 'A' && value <= 'F') {
            return 10 + value - 'A';
        }
        return -1;
    }

} // namespace

bool is_strict_json(QByteArrayView json)
{
    StrictJsonParser parser { json };
    return parser.parse();
}

} // namespace tcp_chat::protocol::detail

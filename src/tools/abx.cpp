// SPDX-License-Identifier: GPL-2.0
#include "abx.hpp"

#include <cstring>

namespace uidfake::abx {
namespace {

/* The four bytes every ABX file starts with. */
constexpr std::uint8_t kMagic[4] = {'A', 'B', 'X', 0};

/* Event codes, in the low nibble of a token byte. */
constexpr std::uint8_t kStartDocument = 0;
constexpr std::uint8_t kEndDocument = 1;
constexpr std::uint8_t kStartTag = 2;
constexpr std::uint8_t kEndTag = 3;
constexpr std::uint8_t kText = 4;
constexpr std::uint8_t kCdataSection = 5;
constexpr std::uint8_t kIgnorableWhitespace = 7;
constexpr std::uint8_t kProcessingInstruction = 8;
constexpr std::uint8_t kComment = 9;
constexpr std::uint8_t kDocDecl = 10;
constexpr std::uint8_t kAttribute = 15;

/* Payload types, in the high nibble. */
constexpr std::uint8_t kNull = 1;
constexpr std::uint8_t kString = 2;
constexpr std::uint8_t kStringInterned = 3;
constexpr std::uint8_t kBytesHex = 4;
constexpr std::uint8_t kBytesBase64 = 5;
constexpr std::uint8_t kInt = 6;
constexpr std::uint8_t kIntHex = 7;
constexpr std::uint8_t kLong = 8;
constexpr std::uint8_t kLongHex = 9;
constexpr std::uint8_t kFloat = 10;
constexpr std::uint8_t kDouble = 11;
constexpr std::uint8_t kTrue = 12;
constexpr std::uint8_t kFalse = 13;

/* The MARKER for a string that is written out rather than referenced. */
constexpr std::uint16_t kNewString = 0xffff;

} // namespace

void Reader::fail() {
  if (!failed_) {
    bad_at_ = pos_;
    bad_byte_ = pos_ < data_.size() ? data_[pos_] : 0;
  }
  failed_ = true;
}

bool Reader::need(std::size_t n) const {
  return !failed_ && pos_ + n <= data_.size();
}

std::uint8_t Reader::u8() {
  if (!need(1)) {
    fail();
    return 0;
  }
  return data_[pos_++];
}

std::uint16_t Reader::u16() {
  if (!need(2)) {
    fail();
    return 0;
  }
  /* Big endian: the format's own writers implement DataOutput, whose multi-byte
   * values are most significant byte first. */
  const std::uint16_t v = static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(data_[pos_]) << 8) | data_[pos_ + 1]);
  pos_ += 2;
  return v;
}

std::uint32_t Reader::u32() {
  if (!need(4)) {
    fail();
    return 0;
  }
  std::uint32_t v = 0;
  for (int i = 0; i < 4; ++i)
    v = (v << 8) | data_[pos_ + static_cast<std::size_t>(i)];
  pos_ += 4;
  return v;
}

std::uint64_t Reader::u64() {
  const std::uint64_t hi = u32();
  const std::uint64_t lo = u32();
  return (hi << 32) | lo;
}

bool Reader::skip(std::size_t n) {
  if (!need(n)) {
    fail();
    return false;
  }
  pos_ += n;
  return true;
}

void Reader::intern(std::string_view s) {
  /* A file that keeps inventing strings is not one this program should keep
   * reading, but the ceiling has to be far above what a real device produces.
   */
  constexpr std::size_t kMaxStrings = 1u << 20;
  if (table_.size() >= kMaxStrings) {
    fail();
    return;
  }
  table_.emplace_back(s);
}

std::string_view Reader::plain_utf() {
  const std::uint16_t len = u16();
  if (failed_ || !need(len)) {
    fail();
    return {};
  }
  const char *raw = reinterpret_cast<const char *>(data_.data() + pos_);
  pos_ += len;

  /* Modified UTF-8: U+0000 arrives as 0xc0 0x80, and the writer may use 4-byte
   * sequences for supplementary planes. */
  constexpr std::size_t kMaxValues = 1u << 20;
  std::string out;
  out.reserve(len);
  for (std::uint16_t i = 0; i < len;) {
    const auto ch = static_cast<std::uint8_t>(raw[i]);
    if (ch < 0x80) {
      out.push_back(static_cast<char>(ch));
      ++i;
      continue;
    }
    if ((ch & 0xe0) == 0xc0 && i + 1 < len) {
      const auto c2 = static_cast<std::uint8_t>(raw[i + 1]);
      out.push_back(
          static_cast<char>((((ch & 0x1f) << 6) | (c2 & 0x3f)) & 0x7f));
      i += 2;
      continue;
    }
    if ((ch & 0xf0) == 0xe0 && i + 2 < len) {
      out.append(raw + i, 3);
      i += 3;
      continue;
    }
    if ((ch & 0xf8) == 0xf0 && i + 3 < len) {
      out.append(raw + i, 4);
      i += 4;
      continue;
    }
    fail();
    return {};
  }

  /* Deliberately not interned: the writer does not add plain strings to the
   * table, so doing it here would shift every later reference. */
  if (values_.size() >= kMaxValues) {
    fail();
    return {};
  }
  values_.emplace_back(std::move(out));
  return std::string_view{values_.back()};
}

std::string_view Reader::interned() {
  const std::uint16_t ref = u16();
  if (failed_)
    return {};

  if (ref != kNewString) {
    /* Every interned string is either written out or referenced, never both: an
     * index outside the table means the stream and this table have drifted
     * apart, which is a reason to stop rather than to guess. */
    if (!in_table(ref)) {
      fail();
      return {};
    }
    return std::string_view{table_[ref]};
  }

  /* A new string: unsigned short length, then modified UTF-8. */
  const std::uint16_t len = u16();
  if (failed_ || !need(len)) {
    fail();
    return {};
  }
  const char *raw = reinterpret_cast<const char *>(data_.data() + pos_);
  pos_ += len;

  /* Modified UTF-8 encodes U+0000 as 0xc0 0x80 and allows 4-byte sequences for
   * supplementary planes. Decode into a plain string; names and paths never
   * contain a NUL, but being correct costs nothing. */
  std::string out;
  out.reserve(len);
  for (std::uint16_t i = 0; i < len;) {
    const auto c = static_cast<std::uint8_t>(raw[i]);
    if (c < 0x80) {
      out.push_back(static_cast<char>(c));
      ++i;
      continue;
    }
    if ((c & 0xe0) == 0xc0 && i + 1 < len) {
      const auto c2 = static_cast<std::uint8_t>(raw[i + 1]);
      const std::uint32_t cp =
          ((c & 0x1f) << 6) | (c2 & 0x3f); /* 0xc0 0x80 folds back to U+0000 */
      out.push_back(static_cast<char>(cp & 0x7f));
      i += 2;
      continue;
    }
    if ((c & 0xf0) == 0xe0 && i + 2 < len) {
      out.append(raw + i, 3);
      i += 3;
      continue;
    }
    if ((c & 0xf8) == 0xf0 && i + 3 < len) {
      out.append(raw + i, 4);
      i += 4;
      continue;
    }
    fail();
    return {};
  }

  intern(out);
  return table_.empty() ? std::string_view{} : std::string_view{table_.back()};
}

Reader::Event Reader::next() {
  Event event;
  if (failed_)
    return event;

  if (pos_ == 0) {
    if (data_.size() < sizeof(kMagic) ||
        std::memcmp(data_.data(), kMagic, sizeof(kMagic)) != 0) {
      fail();
      return event;
    }
    pos_ = sizeof(kMagic);
  }

  for (;;) {
    const std::uint8_t token = u8();
    if (failed_)
      return event;
    const auto type = static_cast<std::uint8_t>(token >> 4);
    const auto code = static_cast<std::uint8_t>(token & 0x0f);

    switch (code) {
    case kStartDocument:
      continue;
    case kEndDocument:
      event.kind = Event::Kind::EndDocument;
      return event;
    case kStartTag:
      event.name = interned();
      if (failed_)
        return event;
      ++depth_;
      event.kind = Event::Kind::StartTag;
      return event;
    case kEndTag:
      event.name = interned();
      if (failed_)
        return event;
      if (depth_ > 0)
        --depth_;
      event.kind = Event::Kind::EndTag;
      return event;
    case kText:
      event.name = type == kString ? plain_utf() : interned();
      if (failed_)
        return event;
      event.kind = Event::Kind::Text;
      return event;
    /*
     * A comment, whitespace, a CDATA section, a processing instruction or a
     * document declaration: each carries one plain string and nothing this
     * reader needs. Real packages.xml files are written by more than one
     * writer, and refusing the whole document over a comment is how a device
     * ends up with no rules at all.
     */
    case kCdataSection:
    case kIgnorableWhitespace:
    case kProcessingInstruction:
    case kComment:
    case kDocDecl:
      (void)plain_utf();
      if (failed_)
        return event;
      continue;
    case kAttribute: {
      event.name = interned();
      if (failed_)
        return event;
      if (type == kString) {
        event.value = plain_utf();
      } else if (type == kStringInterned) {
        event.value = interned();
      } else if (type == kInt || type == kIntHex) {
        event.number = u32();
        event.numeric = true;
      } else if (type == kLong || type == kLongHex) {
        event.number = u64();
        event.numeric = true;
      } else if (type == kTrue || type == kFalse) {
        event.number = type == kTrue ? 1 : 0;
        event.numeric = true;
      } else if (type == kNull) {
        /* no payload */
      } else if (type == kBytesHex || type == kBytesBase64) {
        const std::uint16_t len = u16();
        if (!skip(len))
          return event;
      } else if (type == kFloat) {
        if (!skip(4))
          return event;
      } else if (type == kDouble) {
        if (!skip(8))
          return event;
      } else {
        fail();
        return event;
      }
      if (failed_)
        return event;
      event.kind = Event::Kind::Attribute;
      return event;
    }
    default:
      /* Comments, namespaces, CDATA and anything unknown: not part of a
       * packages.xml document, so a stream containing one is not this format.
       */
      fail();
      return event;
    }
  }
}

bool is_abx(std::span<const std::uint8_t> data) {
  return data.size() >= sizeof(kMagic) &&
         std::memcmp(data.data(), kMagic, sizeof(kMagic)) == 0;
}
} // namespace uidfake::abx

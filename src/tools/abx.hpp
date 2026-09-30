// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <string_view>

#include "packages_xml.hpp"

namespace uidfake::abx {

/*
 * A pull reader for Android Binary XML ("ABX"), the format /data/system writes
 * its XML files in since Android 12.
 *
 * The format is a token stream, not the older resource chunk layout: a byte per
 * event with the payload type in the high nibble and the event in the low one,
 * then the payload. Strings are interned the way FastDataInput/FastDataOutput
 * do it - the first occurrence is written out ("0xffff" marks it, followed by a
 * length in modified UTF-8), every later one is a plain unsigned short index
 * into the table built so far.
 *
 * Only what this program needs is decoded: tags, their names, and attributes
 * with string or integer values. Anything else (bytes, floats, comments,
 * namespaces, a token that is not known at all) ends the stream with Bad: the
 * caller keeps whatever it had instead of acting on a half-read document.
 */
class Reader {
public:
  /* The event type is the one the entry header defines: this reader is one of
   * the two that produce it, and nothing outside the entry uses either. */
  using Event = packages_xml::Event;

  explicit Reader(std::span<const std::uint8_t> data) : data_(data) {}

  /* Next event, or Bad (repeatedly) once the stream cannot be trusted. */
  [[nodiscard]] Event next();

  /* True once the stream is exhausted or broken. */
  [[nodiscard]] bool failed() const { return failed_; }
  /* How many bytes have been consumed: enough for a caller to say where a
   * document stopped being readable. */
  [[nodiscard]] std::size_t position() const { return pos_; }
  /* Where it broke, and the byte it did not understand: what a log line needs
   * to tell a reader which token of a new Android release is unsupported. */
  [[nodiscard]] std::size_t bad_offset() const { return bad_at_; }
  [[nodiscard]] std::uint8_t bad_byte() const { return bad_byte_; }

private:
  [[nodiscard]] bool need(std::size_t n) const;
  [[nodiscard]] std::uint8_t u8();
  [[nodiscard]] std::uint16_t u16();
  [[nodiscard]] std::uint32_t u32();
  [[nodiscard]] std::uint64_t u64();
  [[nodiscard]] bool skip(std::size_t n);
  /* One interned string: 0xffff introduces a new one, anything else is an
   * index into the table. */
  [[nodiscard]] std::string_view interned();
  /* A string written out plainly (TYPE_STRING rather than
   * TYPE_STRING_INTERNED): the same length-prefixed modified UTF-8, without the
   * interning protocol. */
  [[nodiscard]] std::string_view plain_utf();
  /* Remember where the stream stopped and stop for good. */
  void fail();
  /* The interning table; strings live here, views point into it. */
  [[nodiscard]] bool in_table(std::size_t index) const {
    return index < table_.size();
  }
  void intern(std::string_view s);

  std::span<const std::uint8_t> data_;
  std::size_t pos_ = 0;
  std::size_t bad_at_ = 0;
  std::uint8_t bad_byte_ = 0;
  bool failed_ = false;
  int depth_ = 0;
  /* The interning table of the document. A deque, so a string already handed
   * out as a view stays where it is while the table grows; packages.xml on a
   * normal device holds a few thousand of them. */
  std::deque<std::string> table_;
  /* Strings written out plainly (TYPE_STRING values): read, not interned, but
   * they still have to outlive the view handed to the caller. */
  std::deque<std::string> values_;
};

/* True for the binary form: the magic every ABX file starts with. */
[[nodiscard]] bool is_abx(std::span<const std::uint8_t> data);

} // namespace uidfake::abx

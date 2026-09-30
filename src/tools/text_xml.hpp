// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <string_view>

#include "packages_xml.hpp"

namespace uidfake::text_xml {

/* True for the text form: what an XML document starts with, after a byte order
 * mark and whatever whitespace a writer left in front of it. */
[[nodiscard]] bool is_text(std::span<const std::uint8_t> data);

/*
 * The text form of the document, handed out as the same events the binary
 * reader produces: an element's attributes arrive one event each, right after
 * its start tag, and a value that is a decimal or 0x hexadecimal integer
 * arrives as a number.
 *
 * One unit, one job: this file holds the reader for the text form and the XML
 * parser it needs, and nothing else. The tree is walked once when a reader is
 * built, because the events are what a consumer wants and the tree is not; the
 * strings the events point at live here.
 */
class Reader {
public:
  explicit Reader(std::span<const std::uint8_t> data);

  [[nodiscard]] packages_xml::Event next();

  [[nodiscard]] bool failed() const { return failed_; }
  [[nodiscard]] std::size_t position() const { return position_; }
  [[nodiscard]] std::size_t bad_offset() const { return bad_at_; }
  [[nodiscard]] std::uint8_t bad_byte() const { return bad_byte_; }

private:
  std::deque<packages_xml::Event> events_;
  /* The strings the events point at; a deque, so earlier views stay put. */
  std::deque<std::string> owned_;
  std::size_t next_ = 0;
  std::size_t position_ = 0;
  std::size_t bad_at_ = 0;
  std::uint8_t bad_byte_ = 0;
  bool failed_ = false;
};

} // namespace uidfake::text_xml

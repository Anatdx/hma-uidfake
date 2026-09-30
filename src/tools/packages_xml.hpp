// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace uidfake::packages_xml {

/*
 * The package database as a stream of events, whichever form it was written in.
 *
 * The platform writes /data/system/packages.xml in two ways: Android's binary
 * XML (ABX) since Android 12, and plain XML before that, or on a device whose
 * writer never moved. Xml.resolveSerializer() picks between them from the
 * system property persist.sys.binary_xml, and Xml.resolvePullParser() reads a
 * file by sniffing its first four bytes, so both forms live side by side on
 * real devices. This header is the one thing a consumer uses: it hands out the
 * same events either way, so the code that reads packages out of the document
 * cannot drift apart between the two.
 *
 * The readers are separate translation units - abx.cpp for the binary form,
 * text_xml.cpp for the text one - and neither is part of this interface.
 */

struct Event {
  enum class Kind { StartTag, EndTag, Attribute, Text, EndDocument, Bad };

  Kind kind = Kind::Bad;
  /* Tag or attribute name; for Text the text itself. */
  std::string_view name;
  /* String payload of an attribute, or its text form for integers. */
  std::string_view value;
  /* Integer payload, when the attribute carried one. */
  std::uint64_t number = 0;
  bool numeric = false;
};

/* The form these bytes are in, decided by the content and not by trying: the
 * binary magic, or the first character of a text document. Anything else is
 * Unknown, and a caller that says so in its log is how a third writer becomes
 * visible instead of guessed at. */
enum class Form { Binary, Text, Unknown };
[[nodiscard]] Form form(std::span<const std::uint8_t> data);

/* The document, one event at a time. Past a broken document next() gives Bad
 * and failed() stays set, so a half-read file is never acted on. */
class Reader {
public:
  explicit Reader(std::span<const std::uint8_t> data);
  ~Reader();
  Reader(Reader &&) noexcept;
  Reader &operator=(Reader &&) noexcept;
  Reader(const Reader &) = delete;
  Reader &operator=(const Reader &) = delete;

  [[nodiscard]] Event next();

  [[nodiscard]] bool failed() const;
  /* How many bytes were consumed: what a caller reports when a document stopped
   * being readable. */
  [[nodiscard]] std::size_t position() const;
  [[nodiscard]] std::size_t bad_offset() const;
  [[nodiscard]] std::uint8_t bad_byte() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace uidfake::packages_xml

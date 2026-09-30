// SPDX-License-Identifier: GPL-2.0
#include "text_xml.hpp"

#include <utility>
#include <vector>

namespace uidfake::text_xml {
namespace {

/*
 * A small strict reader for the one text document this program meets:
 * /data/system/packages.xml on the builds that write it as XML instead of in
 * Android's binary form. Only what is needed is understood - elements, their
 * attributes, the character data inside them - and what the format allows
 * around that (prolog, comments, CDATA, a doctype) is skipped.
 *
 * Strict where it matters: a document that is not well formed comes back with
 * the offset it stopped at and no tree at all, because acting on half a package
 * database is worse than acting on none - the caller keeps the rules it had.
 * Deliberately not strict about one thing: an entity the reader does not know
 * is copied through as it stands. Refusing a whole document over a writer's
 * stray ampersand is how a device ends up hiding nothing.
 *
 * Written for this program rather than taken from a library: the NDK carries no
 * XML library at all, and what this file is read for is three attributes and a
 * tag name. The shape of the interface follows the small single-header parsers
 * (xml.h among them); the code below is this repository's, and the
 * tag/attribute names, the entities and the nesting are what a packages.xml
 * actually holds.
 */

struct Attribute {
  std::string name;
  std::string value; /* with entities resolved */
};

struct Element {
  std::string name;
  std::vector<Attribute> attributes;
  std::vector<Element> children;

  /* The value of one attribute, empty when it is absent. Attribute lists are
   * short, so a scan is the right lookup. */
  [[nodiscard]] std::string_view attribute(std::string_view key) const;
  [[nodiscard]] bool has(std::string_view key) const {
    return !attribute(key).empty();
  }
};

class Document {
public:
  /* Parse; when this fails, ok() is false and the error says where. */
  [[nodiscard]] static Document parse(std::string_view text);

  [[nodiscard]] bool ok() const { return ok_; }
  [[nodiscard]] const Element &root() const { return root_; }
  /* Where the document stopped being readable, and the byte there. */
  [[nodiscard]] std::size_t error_offset() const { return error_at_; }
  [[nodiscard]] std::uint8_t error_byte() const { return error_byte_; }

private:
  Element root_;
  std::size_t error_at_ = 0;
  std::uint8_t error_byte_ = 0;
  bool ok_ = false;
};

/* packages.xml nests three deep. The ceiling is for the walk below and for the
 * DOM the caller keeps, not a guess at the format: it is high enough that a
 * writer with a taste for nesting still fits. */
constexpr std::size_t kMaxDepth = 256;

[[nodiscard]] bool name_start(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
         c == ':';
}

[[nodiscard]] bool name_char(char c) {
  return name_start(c) || (c >= '0' && c <= '9') || c == '-' || c == '.';
}

[[nodiscard]] bool space(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

[[nodiscard]] int digit_of(char c, bool hex) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (!hex)
    return -1;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Append one code point the way UTF-8 spells it. */
void append_utf8(std::string &out, std::uint32_t code) {
  if (code < 0x80) {
    out.push_back(static_cast<char>(code));
  } else if (code < 0x800) {
    out.push_back(static_cast<char>(0xc0 | (code >> 6)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
  } else if (code < 0x10000) {
    out.push_back(static_cast<char>(0xe0 | (code >> 12)));
    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (code >> 18)));
    out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (code & 0x3f)));
  }
}

/* The five entities XML defines by name. */
constexpr std::pair<std::string_view, char> kNamed[] = {
    {"&amp;", '&'},  {"&lt;", '<'},    {"&gt;", '>'},
    {"&quot;", '"'}, {"&apos;", '\''},
};

class Parser {
public:
  explicit Parser(std::string_view text) : text_(text) {}

  [[nodiscard]] bool parse(Element &root) {
    /* Outside the root element a document may carry the prolog, comments, a
     * doctype and whitespace, and nothing else. */
    if (!skip_misc())
      return false;
    if (!element(root, 0))
      return false;
    if (!skip_misc())
      return false;
    if (!at_end())
      return fail();
    return true;
  }

  [[nodiscard]] std::size_t error_offset() const { return error_at_; }
  [[nodiscard]] std::uint8_t error_byte() const { return error_byte_; }

private:
  [[nodiscard]] bool at_end() const { return pos_ >= text_.size(); }
  [[nodiscard]] char peek() const { return at_end() ? '\0' : text_[pos_]; }
  [[nodiscard]] bool looking_at(std::string_view text) const {
    return text_.compare(pos_, text.size(), text) == 0;
  }

  [[nodiscard]] bool fail() {
    if (!failed_) {
      failed_ = true;
      error_at_ = pos_;
      error_byte_ = at_end() ? 0 : static_cast<std::uint8_t>(text_[pos_]);
    }
    return false;
  }

  bool eat(std::string_view text) {
    if (!looking_at(text))
      return false;
    pos_ += text.size();
    return true;
  }

  void skip_space() {
    while (!at_end() && space(text_[pos_]))
      ++pos_;
  }

  /* Advance past the next occurrence of text; the document ending first is an
   * error, not a place to stop. */
  bool skip_to(std::string_view text) {
    while (!at_end()) {
      if (eat(text))
        return true;
      ++pos_;
    }
    return fail();
  }

  /* A name: the tag or attribute name as written. */
  bool name(std::string &out) {
    if (at_end() || !name_start(text_[pos_]))
      return fail();
    const std::size_t start = pos_;
    while (!at_end() && name_char(text_[pos_]))
      ++pos_;
    out.assign(text_.substr(start, pos_ - start));
    return true;
  }

  /* A quoted attribute value, entities resolved. */
  bool quoted(std::string &out) {
    if (at_end() || (peek() != '"' && peek() != '\''))
      return fail();
    const char quote = text_[pos_++];
    while (!at_end() && text_[pos_] != quote) {
      if (text_[pos_] != '&') {
        out.push_back(text_[pos_++]);
        continue;
      }
      if (!entity(out))
        return false;
    }
    if (at_end())
      return fail();
    ++pos_; /* the closing quote */
    return true;
  }

  /* One entity. The five named ones and the numeric forms are resolved;
   * anything else is copied through as written, because a writer's stray
   * ampersand must not cost the device every rule it has. */
  bool entity(std::string &out) {
    for (const auto &[text, replacement] : kNamed) {
      if (looking_at(text)) {
        out.push_back(replacement);
        pos_ += text.size();
        return true;
      }
    }
    if (!looking_at("&#")) {
      out.push_back(text_[pos_++]);
      return true;
    }

    const std::size_t start = pos_;
    pos_ += 2;
    const bool hex = !at_end() && (peek() == 'x' || peek() == 'X');
    if (hex)
      ++pos_;
    std::uint32_t code = 0;
    std::size_t digits = 0;
    while (!at_end() && digits < 7) {
      const int value = digit_of(peek(), hex);
      if (value < 0)
        break;
      code = code * (hex ? 16u : 10u) + static_cast<std::uint32_t>(value);
      ++pos_;
      ++digits;
    }
    if (digits == 0 || at_end() || peek() != ';' || code == 0 ||
        code > 0x10ffff) {
      /* Not a reference after all: put it back and keep going. */
      pos_ = start;
      out.push_back(text_[pos_++]);
      return true;
    }
    ++pos_; /* the semicolon */
    append_utf8(out, code);
    return true;
  }

  /* <!DOCTYPE ...>, with the internal subset in brackets and quotes that may
   * contain either bracket or the closing angle. */
  bool skip_declaration() {
    std::size_t brackets = 0;
    char quote = '\0';
    while (!at_end()) {
      const char c = text_[pos_++];
      if (quote != '\0') {
        if (c == quote)
          quote = '\0';
        continue;
      }
      if (c == '"' || c == '\'')
        quote = c;
      else if (c == '[')
        ++brackets;
      else if (c == ']') {
        if (brackets > 0)
          --brackets;
      } else if (c == '>' && brackets == 0) {
        return true;
      }
    }
    return fail();
  }

  /* The prolog, comments, a doctype: everything a document may hold outside the
   * root element and inside it, where character data is not wanted. */
  bool skip_misc() {
    for (;;) {
      skip_space();
      if (looking_at("<?")) {
        if (!skip_to("?>"))
          return false;
        continue;
      }
      if (looking_at("<!--")) {
        if (!skip_to("-->"))
          return false;
        continue;
      }
      if (looking_at("<!")) {
        if (!skip_declaration())
          return false;
        continue;
      }
      return true;
    }
  }

  bool element(Element &out, std::size_t depth) {
    if (depth > kMaxDepth)
      return fail();
    /* The caller may have stopped at the whitespace in front of the tag. */
    skip_space();
    if (!eat("<"))
      return fail();
    if (!name(out.name))
      return false;

    /* Attributes, then either the end of an empty element or the start of its
     * content. */
    for (;;) {
      skip_space();
      if (eat("/>"))
        return true;
      if (eat(">"))
        break;
      Attribute attribute;
      if (!name(attribute.name))
        return false;
      skip_space();
      if (!eat("="))
        return fail();
      skip_space();
      if (!quoted(attribute.value))
        return false;
      out.attributes.push_back(std::move(attribute));
    }

    for (;;) {
      if (!skip_misc())
        return false;
      if (at_end())
        return fail();
      if (looking_at("</")) {
        /* The two ends of a tag have to say the same thing: a file that does
         * not is one to refuse, not one to read half of. */
        std::string close;
        if (!eat("</") || !name(close))
          return false;
        if (close != out.name)
          return fail();
        skip_space();
        return eat(">") ? true : fail();
      }
      if (looking_at("<![CDATA[")) {
        if (!skip_to("]]>"))
          return false;
        continue;
      }
      if (looking_at("<")) {
        out.children.emplace_back();
        if (!element(out.children.back(), depth + 1))
          return false;
        continue;
      }

      /* Character data between elements: none of it is read, so it is skipped
       * to the next tag. */
      while (!at_end() && text_[pos_] != '<')
        ++pos_;
    }
  }

  std::string_view text_;
  std::size_t pos_ = 0;
  std::size_t error_at_ = 0;
  std::uint8_t error_byte_ = 0;
  bool failed_ = false;
};

std::string_view Element::attribute(std::string_view key) const {
  for (const auto &attribute : attributes)
    if (attribute.name == key)
      return attribute.value;
  return {};
}

Document Document::parse(std::string_view text) {
  Document document;
  /* A byte order mark in front of the declaration is part of the file, not of
   * the document. */
  if (text.size() >= 3 && static_cast<std::uint8_t>(text[0]) == 0xef &&
      static_cast<std::uint8_t>(text[1]) == 0xbb &&
      static_cast<std::uint8_t>(text[2]) == 0xbf)
    text.remove_prefix(3);

  Parser parser{text};
  if (!parser.parse(document.root_)) {
    document.error_at_ = parser.error_offset();
    document.error_byte_ = parser.error_byte();
    return document;
  }
  document.ok_ = true;
  return document;
}

/* A value that is an integer, in either notation the writers use. */
[[nodiscard]] bool number_of(std::string_view text, std::uint64_t &out) {
  if (text.empty())
    return false;
  bool negative = false;
  if (text.front() == '-') {
    negative = true;
    text.remove_prefix(1);
  }
  if (text.empty())
    return false;

  std::uint64_t value = 0;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    text.remove_prefix(2);
    for (const char c : text) {
      int digit = -1;
      if (c >= '0' && c <= '9')
        digit = c - '0';
      else if (c >= 'a' && c <= 'f')
        digit = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        digit = c - 'A' + 10;
      if (digit < 0)
        return false;
      value = value * 16 + static_cast<std::uint64_t>(digit);
    }
  } else {
    for (const char c : text) {
      if (c < '0' || c > '9')
        return false;
      value = value * 10 + static_cast<std::uint64_t>(c - '0');
    }
  }
  out = negative ? (~value + 1) : value;
  return true;
}

/* One element and everything under it, in the order a consumer reads. */
void walk(const Element &element, std::deque<packages_xml::Event> &events,
          std::deque<std::string> &owned) {
  const auto keep = [&owned](std::string_view text) {
    owned.emplace_back(text);
    return std::string_view{owned.back()};
  };

  packages_xml::Event start;
  start.kind = packages_xml::Event::Kind::StartTag;
  start.name = keep(element.name);
  events.push_back(start);

  /* The binary stream carries an element's attributes one event each, right
   * after its start tag; the same order keeps one consumer loop for both. */
  for (const auto &attribute : element.attributes) {
    packages_xml::Event event;
    event.kind = packages_xml::Event::Kind::Attribute;
    event.name = keep(attribute.name);
    event.value = keep(attribute.value);
    event.numeric = number_of(event.value, event.number);
    events.push_back(event);
  }

  for (const auto &child : element.children)
    walk(child, events, owned);

  packages_xml::Event end;
  end.kind = packages_xml::Event::Kind::EndTag;
  end.name = start.name;
  events.push_back(end);
}

} // namespace

bool is_text(std::span<const std::uint8_t> data) {
  std::size_t i = 0;
  /* A byte order mark, then whatever whitespace a writer left in front. */
  if (data.size() >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf)
    i = 3;
  while (i < data.size() && (data[i] == ' ' || data[i] == '\t' ||
                             data[i] == '\r' || data[i] == '\n'))
    ++i;
  return i < data.size() && data[i] == '<';
}

Reader::Reader(std::span<const std::uint8_t> data) {
  const std::string_view text{reinterpret_cast<const char *>(data.data()),
                              data.size()};
  const Document document = Document::parse(text);
  position_ = text.size();
  if (!document.ok()) {
    failed_ = true;
    bad_at_ = document.error_offset();
    bad_byte_ = document.error_byte();
    return;
  }
  walk(document.root(), events_, owned_);
}

packages_xml::Event Reader::next() {
  packages_xml::Event event;
  if (failed_)
    return event;
  if (next_ >= events_.size()) {
    event.kind = packages_xml::Event::Kind::EndDocument;
    return event;
  }
  return events_[next_++];
}

} // namespace uidfake::text_xml

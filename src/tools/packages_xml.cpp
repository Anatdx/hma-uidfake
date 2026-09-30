// SPDX-License-Identifier: GPL-2.0
#include "packages_xml.hpp"

#include "abx.hpp"
#include "text_xml.hpp"

namespace uidfake::packages_xml {
namespace {

/*
 * What the entry hands its callers: one of the two readers, behind the
 * interface this header describes. Neither reader appears in it, and this is
 * the only place that knows there are two.
 */
class Source {
public:
  Source() = default;
  virtual ~Source() = default;
  Source(const Source &) = delete;
  Source &operator=(const Source &) = delete;
  Source(Source &&) = delete;
  Source &operator=(Source &&) = delete;

  [[nodiscard]] virtual Event next() = 0;
  [[nodiscard]] virtual bool failed() const = 0;
  [[nodiscard]] virtual std::size_t position() const = 0;
  [[nodiscard]] virtual std::size_t bad_offset() const = 0;
  [[nodiscard]] virtual std::uint8_t bad_byte() const = 0;
};

class BinarySource : public Source {
public:
  explicit BinarySource(std::span<const std::uint8_t> data) : reader_(data) {}

  [[nodiscard]] Event next() override { return reader_.next(); }
  [[nodiscard]] bool failed() const override { return reader_.failed(); }
  [[nodiscard]] std::size_t position() const override {
    return reader_.position();
  }
  [[nodiscard]] std::size_t bad_offset() const override {
    return reader_.bad_offset();
  }
  [[nodiscard]] std::uint8_t bad_byte() const override {
    return reader_.bad_byte();
  }

private:
  abx::Reader reader_;
};

class TextSource : public Source {
public:
  explicit TextSource(std::span<const std::uint8_t> data) : reader_(data) {}

  [[nodiscard]] Event next() override { return reader_.next(); }
  [[nodiscard]] bool failed() const override { return reader_.failed(); }
  [[nodiscard]] std::size_t position() const override {
    return reader_.position();
  }
  [[nodiscard]] std::size_t bad_offset() const override {
    return reader_.bad_offset();
  }
  [[nodiscard]] std::uint8_t bad_byte() const override {
    return reader_.bad_byte();
  }

private:
  text_xml::Reader reader_;
};

} // namespace

Form form(std::span<const std::uint8_t> data) {
  if (abx::is_abx(data))
    return Form::Binary;
  if (text_xml::is_text(data))
    return Form::Text;
  return Form::Unknown;
}

struct Reader::Impl {
  std::unique_ptr<Source> source;
};

Reader::Reader(std::span<const std::uint8_t> data)
    : impl_(std::make_unique<Impl>()) {
  /* Only the reader the bytes call for is built: the text one reads its whole
   * document when it is constructed, and that is work a binary file must not
   * pay for. */
  if (abx::is_abx(data))
    impl_->source = std::make_unique<BinarySource>(data);
  else
    impl_->source = std::make_unique<TextSource>(data);
}

Reader::~Reader() = default;
Reader::Reader(Reader &&) noexcept = default;
Reader &Reader::operator=(Reader &&) noexcept = default;

Event Reader::next() { return impl_->source->next(); }
bool Reader::failed() const { return impl_->source->failed(); }
std::size_t Reader::position() const { return impl_->source->position(); }
std::size_t Reader::bad_offset() const { return impl_->source->bad_offset(); }
std::uint8_t Reader::bad_byte() const { return impl_->source->bad_byte(); }

} // namespace uidfake::packages_xml

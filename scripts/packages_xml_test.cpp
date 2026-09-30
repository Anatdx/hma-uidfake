// SPDX-License-Identifier: GPL-2.0
/*
 * Host test for the entry both readers sit behind: which form a file is taken
 * for, the events the text form produces, and what it refuses. The binary side is
 * checked with the first 64 bytes of a real packages.xml, so the routing is
 * exercised on the format itself and not on a description of it.
 *
 * The two readers are separate translation units (abx.cpp and text_xml.cpp), and
 * nothing outside the entry header knows which one ran. That is the property
 * under test here, together with the text parser's manners, which are the ones a
 * packages.xml from several devices asked for: a byte order mark, a prolog,
 * comments, a doctype, CDATA, the five named entities and the numeric ones, and
 * around them the damage a torn write or a foreign writer leaves behind - junk in
 * front, padding behind, an unfinished tag, attribute, comment or CDATA section.
 *
 * Two cases are tolerated rather than refused, on purpose: an entity the parser
 * does not know is kept as written, and a repeated attribute keeps its first
 * value. Refusing a whole package database over either would cost a device every
 * rule it has, and neither can be used to hide a package.
 */
#include "packages_xml.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace
{

int failures = 0;

void check(bool got, bool want, const char *what)
{
	if (got == want)
		return;
	std::fprintf(stderr, "packages-xml: FAILED (%s: got %d, want %d)\n",
		     what, got, want);
	++failures;
}

std::span<const std::uint8_t> bytes_of(std::string_view text)
{
	return { reinterpret_cast<const std::uint8_t *>(text.data()),
		 text.size() };
}

std::string nested(int depth)
{
	std::string text;
	for (int i = 0; i < depth; ++i)
		text += "<a>";
	for (int i = 0; i < depth; ++i)
		text += "</a>";
	return text;
}

/* A text document read, and the root element it has to start with. */
void accept_text(const char *label, const std::string &text,
		 std::string_view root)
{
	uidfake::packages_xml::Reader reader{ bytes_of(text) };
	const auto first = reader.next();
	if (first.kind != uidfake::packages_xml::Event::Kind::StartTag ||
	    first.name != root) {
		std::fprintf(stderr, "packages-xml: FAILED (%s: no <%s>)\n",
			     label, std::string{ root }.c_str());
		++failures;
	}
}

/* A text document refused, and where the reader has to say it stopped. */
void refuse_text(const char *label, const std::string &text, std::size_t offset)
{
	uidfake::packages_xml::Reader reader{ bytes_of(text) };
	(void)reader.next();
	if (!reader.failed()) {
		std::fprintf(stderr, "packages-xml: FAILED (%s: not refused)\n",
			     label);
		++failures;
		return;
	}
	if (reader.bad_offset() != offset) {
		std::fprintf(
			stderr,
			"packages-xml: FAILED (%s: stopped at %zu, want %zu)\n",
			label, reader.bad_offset(), offset);
		++failures;
	}
}

/* Refused wherever it stopped: for the cases where the ceiling is the point. */
void refuse_anywhere(const char *label, const std::string &text)
{
	uidfake::packages_xml::Reader reader{ bytes_of(text) };
	(void)reader.next();
	if (!reader.failed()) {
		std::fprintf(stderr, "packages-xml: FAILED (%s: not refused)\n",
			     label);
		++failures;
	}
}

/* The first 64 bytes of a real /data/system/packages.xml: "ABX\0", the document
 * start, <packages>, <version> and the sdkVersion attribute, then a cut string. */
const std::uint8_t kBinary[] = {
	0x41, 0x42, 0x58, 0x00, 0x10, 0x32, 0xff, 0xff, 0x00, 0x08, 'p',
	'a',  'c',  'k',  'a',	'g',  'e',  's',  0x32, 0xff, 0xff, 0x00,
	0x07, 'v',  'e',  'r',	's',  'i',  'o',  'n',	0x6f, 0xff, 0xff,
	0x00, 0x0a, 's',  'd',	'k',  'V',  'e',  'r',	's',  'i',  'o',
	'n',  0x00, 0x00, 0x00, 0x25, 0x6f, 0xff, 0xff, 0x00, 0x0e, 's',
	'd',  'k',  'V',  'e',	'r',  's',  'i',  'o',	'n'
};

constexpr auto kText =
	R"(<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<packages>
    <!-- a comment -->
    <version sdkVersion="36" />
    <package name="com.example.app" codePath="/data/app/~~a/com.example.app-b/base.apk" userId="10427" publicFlags="1">
        <perms />
    </package>
</packages>
)";

void test_form()
{
	using Form = uidfake::packages_xml::Form;
	check(uidfake::packages_xml::form(bytes_of("<a/>")) == Form::Text, true,
	      "a tag is the text form");
	check(uidfake::packages_xml::form(
		      bytes_of("<?xml version='1.0'?><a/>")) == Form::Text,
	      true, "so is a prolog");
	check(uidfake::packages_xml::form(bytes_of("\xEF\xBB\xBF<a/>")) ==
		      Form::Text,
	      true, "a byte order mark does not hide it");
	check(uidfake::packages_xml::form(kBinary) == Form::Binary, true,
	      "the magic is the binary form");
	check(uidfake::packages_xml::form(bytes_of("")) == Form::Unknown, true,
	      "an empty file is neither");
	check(uidfake::packages_xml::form(bytes_of(
		      std::string("\xFF\xFE<\0a\0", 6))) == Form::Unknown,
	      true, "nor is utf-16");
	check(uidfake::packages_xml::form(
		      bytes_of(std::string(4, '\0') + "<a/>")) == Form::Unknown,
	      true, "nor is padding in front of one");
}

void test_text_events()
{
	uidfake::packages_xml::Reader reader{ bytes_of(kText) };
	using Kind = uidfake::packages_xml::Event::Kind;

	auto event = reader.next();
	check(event.kind == Kind::StartTag && event.name == "packages", true,
	      "text: the root starts");

	event = reader.next();
	check(event.kind == Kind::StartTag && event.name == "version", true,
	      "text: a self-closing tag still starts");
	event = reader.next();
	check(event.kind == Kind::Attribute && event.name == "sdkVersion" &&
		      event.numeric && event.number == 36,
	      true, "text: an integer attribute arrives as a number");
	event = reader.next();
	check(event.kind == Kind::EndTag && event.name == "version", true,
	      "text: and it closes");

	event = reader.next();
	check(event.kind == Kind::StartTag && event.name == "package", true,
	      "text: the package element starts");
	event = reader.next();
	check(event.kind == Kind::Attribute && event.name == "name" &&
		      event.value == "com.example.app" && !event.numeric,
	      true, "text: its name is a string");
	event = reader.next();
	check(event.kind == Kind::Attribute && event.name == "codePath" &&
		      !event.numeric,
	      true, "text: so is its code path");
	event = reader.next();
	check(event.kind == Kind::Attribute && event.name == "userId" &&
		      event.numeric && event.number == 10427,
	      true, "text: the app id arrives as a number");
	event = reader.next();
	check(event.kind == Kind::Attribute && event.name == "publicFlags" &&
		      event.numeric && event.number == 1,
	      true, "text: and so does the flags word");
	event = reader.next();
	check(event.kind == Kind::StartTag && event.name == "perms", true,
	      "text: a nested element follows its parent");
	event = reader.next();
	check(event.kind == Kind::EndTag && event.name == "perms", true,
	      "text: and closes");
	event = reader.next();
	check(event.kind == Kind::EndTag && event.name == "package", true,
	      "text: the package element closes");
	event = reader.next();
	check(event.kind == Kind::EndTag && event.name == "packages", true,
	      "text: the root closes");
	event = reader.next();
	check(event.kind == Kind::EndDocument, true, "text: the document ends");
	check(!reader.failed(), true, "text: and it was read without an error");
}

void test_text_accepted()
{
	const std::string bom = std::string("\xEF\xBB\xBF");
	const std::string decl =
		"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>";
	accept_text("plain", "<a/>", "a");
	accept_text("prolog", decl + "<a/>", "a");
	accept_text("bom and prolog", bom + decl + "<a/>", "a");
	accept_text("leading whitespace", "\n\t  " + decl + "<a/>", "a");
	accept_text("leading comment", "<!-- c -->" + decl + "<a/>", "a");
	accept_text("trailing whitespace", "<a/>\n\n", "a");
	accept_text("trailing comment", "<a/><!-- c -->", "a");
	accept_text("cdata", "<a><![CDATA[<b/>]]></a>", "a");
	accept_text("doctype",
		    "<!DOCTYPE a [ <!ENTITY x \"y\"> ]><a b=\"&x;\"/>", "a");
	accept_text("unknown entity kept", "<a b=\"x&foo;y\"/>", "a");
	accept_text("duplicate attribute", "<a b=\"1\" b=\"2\"/>", "a");
	accept_text("nested 20", nested(20), "a");
	accept_text("nested 200", nested(200), "a");
}

void test_text_refused()
{
	refuse_anywhere("nested 400 is past the ceiling", nested(400));
	refuse_text("empty", "", 0);
	refuse_text("prolog only",
		    "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>",
		    56);
	refuse_text("leading NUL padding", std::string(4, '\0') + "<a/>", 0);
	refuse_text("leading junk", "junk<a/>", 0);
	refuse_text("utf-16", std::string("\xFF\xFE<\0a\0/\0>\0", 10), 0);
	refuse_text("trailing junk", "<a/>junk", 4);
	refuse_text("trailing NUL padding",
		    std::string("<a/>") + std::string(2, '\0'), 4);
	refuse_text("mismatched end tag", "<a></b>", 6);
	refuse_text("unclosed tag", "<a>", 3);
	refuse_text("unfinished attribute", "<a b=\"x/>", 9);
	refuse_text("unfinished comment", "<!-- x <a/>", 11);
	refuse_text("unfinished cdata", "<a><![CDATA[x</a>", 17);
}

/* Entities are resolved in a value, which is the only place a consumer sees one. */
void test_entity_values()
{
	uidfake::packages_xml::Reader reader{ bytes_of(
		"<a b=\"&amp;&lt;&#65;&#x42;\" c=\"&quot;q&quot;\"/>") };
	using Kind = uidfake::packages_xml::Event::Kind;
	(void)reader.next();
	const auto b = reader.next();
	check(b.kind == Kind::Attribute && b.name == "b" && b.value == "&<AB",
	      true, "entities decode");
	const auto c = reader.next();
	check(c.kind == Kind::Attribute && c.name == "c" && c.value == "\"q\"",
	      true, "quotes decode too");
}

void test_binary_events()
{
	uidfake::packages_xml::Reader reader{ kBinary };
	using Kind = uidfake::packages_xml::Event::Kind;

	auto event = reader.next();
	check(event.kind == Kind::StartTag && event.name == "packages", true,
	      "binary: the root starts");
	event = reader.next();
	check(event.kind == Kind::StartTag && event.name == "version", true,
	      "binary: the version element starts");
	event = reader.next();
	check(event.kind == Kind::Attribute && event.name == "sdkVersion" &&
		      event.numeric && event.number == 37,
	      true, "binary: the integer attribute arrives as a number");
	(void)reader.next();
	check(reader.failed(), true,
	      "binary: the cut sample is refused, not half read");
}

} // namespace

int main()
{
	test_form();
	test_text_events();
	test_text_accepted();
	test_text_refused();
	test_entity_values();
	test_binary_events();
	if (failures != 0) {
		std::fprintf(stderr, "packages-xml: %d case(s) failed\n",
			     failures);
		return 1;
	}
	std::printf("packages-xml: PASS\n");
	return 0;
}

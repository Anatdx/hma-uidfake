#!/usr/bin/env bash
# Format check for the files clang-format and clang-tidy never look at.
#
#   C and C++   clang-format --dry-run -Werror, over every tracked source file
#   shell       bash -n, and no leading tabs (recipes aside, these files are indented with spaces)
#   the rest    no tabs, no trailing whitespace, LF endings, a newline at the end
#
# Everything the check looks at is tracked by git, so build output and .scratch stay out of it.
set -eu
cd "$(dirname "$0")/.."

fail=0
note() {
  echo "  $1"
  fail=1
}

# ---- C and C++ ------------------------------------------------------------
mapfile -t cxx < <(git ls-files '*.c' '*.cc' '*.cpp' '*.h' '*.hpp')
echo "clang-format: ${#cxx[@]} files"
if ! diff=$(clang-format --dry-run -Werror "${cxx[@]}" 2>&1); then
  printf '%s\n' "$diff" | sed 's/^/  /'
  note 'clang-format found differences'
fi

# ---- whitespace and line endings -----------------------------------------
mapfile -t text < <(git ls-files | grep -vE '\.(png|jpg|gif|zip|ko|apk|jar|so)$')
echo "whitespace: ${#text[@]} files"
for f in "${text[@]}"; do
  [ -f "$f" ] || continue # gitlinks name directories, not project text files
  # Kernel sources and Makefile recipes are indented with tabs by their own rules, so the tab
  # check only covers the file types this repository writes itself.
  case "$f" in
  *.sh | *.yml | *.yaml | *.prop | *.md | *.txt | *.cmake | CMakeLists.txt | */CMakeLists.txt)
    grep -qP '\t' "$f" && note "$f: contains a tab"
    ;;
  esac
  grep -qE ' +$' "$f" && note "$f: trailing whitespace"
  grep -qU $'\r' "$f" && note "$f: CRLF line ending"
  [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ] && note "$f: no newline at end of file"
done

# ---- shell ---------------------------------------------------------------
mapfile -t sh < <(git ls-files '*.sh')
echo "shell: ${#sh[@]} files"
for f in "${sh[@]}"; do bash -n "$f" || note "$f: syntax"; done

echo
if [ "$fail" = 0 ]; then
  echo 'format: OK'
else
  echo 'format: FAILED'
fi
exit "$fail"

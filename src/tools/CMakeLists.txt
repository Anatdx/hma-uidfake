cmake_minimum_required(VERSION 3.20)
project(uidfake-tools LANGUAGES CXX)

add_compile_options(-Wall)

# sync-tool: one process that watches HMA's config, evaluates it and pushes the
# resulting policy to the kernel over netlink.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(nlohmann_json REQUIRED)

add_executable(sync-tool
    abx.cpp
    text_xml.cpp
    packages_xml.cpp
    main.cpp
    sync.cpp
    watcher.cpp
    netlink.cpp
    status.cpp
    rules.cpp
  preset_rules.cpp
    packages.cpp
    paths.cpp
    paging.cpp)

target_link_libraries(sync-tool PRIVATE nlohmann_json::nlohmann_json dl z)
# Resolved at run time on purpose: __system_property_wait() and __system_property_serial() are
# platform-only (the NDK stubs carry no symbol for them), and a dynamic link is what lets dlsym()
# find them - with -static the NDK links its libdl.a stub, whose dlopen() always fails. libc++
# stays static, so nothing extra ships.


target_compile_options(sync-tool PRIVATE -O2 -Wall -Wextra)
target_link_options(sync-tool PRIVATE -s)

# Cross compiling with the NDK: CMake filters the package's /usr/include out as an
# implicit directory, and the NDK's clang does not search the host /usr/include
# anyway. Adding /usr/include directly makes host C headers shadow libc++'s (which
# then #errors), so build a header root in the build tree that only contains nlohmann.
if(CMAKE_CROSSCOMPILING)
  get_target_property(_nlj_incs nlohmann_json::nlohmann_json INTERFACE_INCLUDE_DIRECTORIES)
  list(GET _nlj_incs 0 _nlj_root)
  set(_hdr_root "${CMAKE_BINARY_DIR}/include")
  file(MAKE_DIRECTORY "${_hdr_root}")
  file(REMOVE_RECURSE "${_hdr_root}/nlohmann")
  file(CREATE_LINK "${_nlj_root}/nlohmann" "${_hdr_root}/nlohmann" SYMBOLIC RESULT _lnk)
  target_include_directories(sync-tool PRIVATE "${_hdr_root}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../include")
  message(STATUS "nlohmann/json: header root ${_hdr_root} -> ${_nlj_root}/nlohmann")
endif()

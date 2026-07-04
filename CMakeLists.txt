cmake_minimum_required(VERSION 3.25)
project(prout LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "Prefer static libraries")
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

include(FetchContent)

set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  abseil
  GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
  GIT_TAG        20250127.1
)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.11.3
)

set(CURL_STATICLIB     ON  CACHE BOOL     "Build cURL as a static library" FORCE)
set(BUILD_CURL_EXE     OFF CACHE BOOL     "Skip the curl command-line tool" FORCE)
set(HTTP_ONLY          ON  CACHE BOOL     "Only HTTP/HTTPS protocols" FORCE)
set(CURL_DISABLE_TESTS ON  CACHE INTERNAL "Disable curl tests")
set(BUILD_LIBCURL_DOCS OFF CACHE INTERNAL "Disable docs")
set(BUILD_MISC_DOCS    OFF CACHE INTERNAL "Disable misc docs")
set(ENABLE_CURL_MANUAL OFF CACHE INTERNAL "Disable manual")
set(CURL_USE_LIBPSL    OFF CACHE BOOL     "Disable libpsl support" FORCE)
set(CURL_USE_LIBSSH2   OFF CACHE BOOL     "Disable libssh2 support" FORCE)
set(CURL_BROTLI        OFF CACHE BOOL     "Disable Brotli" FORCE)
set(CURL_ZSTD          OFF CACHE BOOL     "Disable ZSTD" FORCE)

if(WIN32)
  set(CURL_USE_SCHANNEL ON  CACHE BOOL "Windows-native SSL/TLS (Schannel)" FORCE)
  set(CURL_USE_OPENSSL  OFF CACHE BOOL "No OpenSSL on Windows" FORCE)
else()
  set(CURL_USE_OPENSSL ON CACHE BOOL "Use OpenSSL for TLS" FORCE)
endif()

FetchContent_Declare(
  curl
  GIT_REPOSITORY https://github.com/curl/curl.git
  GIT_TAG        curl-8_12_1
)
FetchContent_MakeAvailable(abseil nlohmann_json curl)

set(LITERT_LM_ROOT "${CMAKE_SOURCE_DIR}/third_party/litert-lm"
    CACHE PATH "Root of the vendored LiteRT-LM submodule")
set(LITERT_LM_LIB_DIR "${LITERT_LM_ROOT}/bazel-bin/c"
    CACHE PATH "Directory containing the built LiteRT-LM C ABI shared library")

add_library(litert_lm SHARED IMPORTED GLOBAL)
set_target_properties(litert_lm PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${LITERT_LM_ROOT}")

if(WIN32)
  set(LITERT_LM_DLL "${LITERT_LM_LIB_DIR}/litert-lm.dll"
      CACHE FILEPATH "Path to litert-lm.dll")
  set(LITERT_LM_IMPLIB "${LITERT_LM_LIB_DIR}/litert-lm.if.lib"
      CACHE FILEPATH "Path to the litert-lm import library (.lib)")
  set_target_properties(litert_lm PROPERTIES
    IMPORTED_LOCATION "${LITERT_LM_DLL}"
    IMPORTED_IMPLIB   "${LITERT_LM_IMPLIB}")
elseif(APPLE)
  set(LITERT_LM_DYLIB "${LITERT_LM_LIB_DIR}/liblitert-lm.dylib"
      CACHE FILEPATH "Path to liblitert-lm.dylib")
  set_target_properties(litert_lm PROPERTIES IMPORTED_LOCATION "${LITERT_LM_DYLIB}")
else()
  set(LITERT_LM_SO "${LITERT_LM_LIB_DIR}/liblitert-lm.so"
      CACHE FILEPATH "Path to liblitert-lm.so")
  set_target_properties(litert_lm PROPERTIES IMPORTED_LOCATION "${LITERT_LM_SO}")
endif()

add_executable(prout
  src/cli/main.cc
  src/cli/client.cc
  src/cli/vault_cmd.cc
  src/cli/audit_cmd.cc
  src/daemon/serve.cc
  src/daemon/lease.cc
  src/ipc/ipc.cc
  src/vault/vault.cc
  src/vault/crypto.cc
  src/audit/audit.cc
  src/arbiter/arbiter.cc
  src/common/paths.cc
  src/common/prompt.cc
  src/common/secure_mem.cc
  third_party/monocypher/monocypher.c)

target_include_directories(prout PRIVATE
  "${CMAKE_SOURCE_DIR}/src"
  "${CMAKE_SOURCE_DIR}/third_party/monocypher"
  "${curl_SOURCE_DIR}/include")

target_link_libraries(prout PRIVATE
  CURL::libcurl
  litert_lm
  nlohmann_json::nlohmann_json
  absl::status
  absl::statusor)

if(WIN32)
  target_link_libraries(prout PRIVATE ws2_32 crypt32 bcrypt advapi32)
  target_compile_definitions(prout PRIVATE _WIN32_WINNT=0x0600 CURL_STATICLIB NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

set(PROUT_DIST_DIR "${CMAKE_SOURCE_DIR}/dist")

if(WIN32)
  set(LITERT_LM_CONSTRAINT_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libGemmaModelConstraintProvider.dll"
      CACHE FILEPATH "Path to libGemmaModelConstraintProvider.dll")
  set(LITERT_RUNTIME_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libLiteRt.dll"
      CACHE FILEPATH "Path to libLiteRt.dll")
  set(LITERT_WEBGPU_ACCELERATOR_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libLiteRtWebGpuAccelerator.dll"
      CACHE FILEPATH "Path to libLiteRtWebGpuAccelerator.dll")
  set(LITERT_TOPK_WEBGPU_SAMPLER_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libLiteRtTopKWebGpuSampler.dll"
      CACHE FILEPATH "Path to libLiteRtTopKWebGpuSampler.dll")
  set(LITERT_TOPK_OPENCL_SAMPLER_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libLiteRtTopKOpenClSampler.dll"
      CACHE FILEPATH "Path to libLiteRtTopKOpenClSampler.dll")
  set(LITERT_OPENCL_ACCELERATOR_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libLiteRtOpenClAccelerator.dll"
      CACHE FILEPATH "Path to libLiteRtOpenClAccelerator.dll")
  set(LITERT_GPU_ACCELERATOR_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libLiteRtGpuAccelerator.dll"
      CACHE FILEPATH "Path to libLiteRtGpuAccelerator.dll")
  set(LITERT_WEBGPU_DAWN_DLL
      "${LITERT_LM_ROOT}/prebuilt/windows_x86_64/libwebgpu_dawn.dll"
      CACHE FILEPATH "Path to libwebgpu_dawn.dll")
  set(DXC_REDIST_HINTS
      "$ENV{WindowsSdkDir}bin/$ENV{WindowsSDKVersion}/x64"
      "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64"
      "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x64"
      "$ENV{WindowsSdkDir}Redist/D3D/x64"
      "C:/Program Files (x86)/Windows Kits/10/Redist/D3D/x64")
  find_file(PROUT_DXIL_DLL
      NAMES dxil.dll
      HINTS ${DXC_REDIST_HINTS}
      REQUIRED)
  find_file(PROUT_DXCOMPILER_DLL
      NAMES dxcompiler.dll
      HINTS ${DXC_REDIST_HINTS}
      REQUIRED)

  add_custom_command(TARGET prout POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${PROUT_DIST_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:prout>" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LITERT_LM_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LITERT_LM_CONSTRAINT_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LITERT_RUNTIME_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LITERT_WEBGPU_ACCELERATOR_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LITERT_WEBGPU_DAWN_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${PROUT_DXIL_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${PROUT_DXCOMPILER_DLL}" "${PROUT_DIST_DIR}/"
    COMMAND ${CMAKE_COMMAND}
            -DSRC="${LITERT_TOPK_WEBGPU_SAMPLER_DLL}"
            -DDST_DIR="${PROUT_DIST_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/copy_if_exists.cmake"
    COMMAND ${CMAKE_COMMAND}
            -DSRC="${LITERT_TOPK_OPENCL_SAMPLER_DLL}"
            -DDST_DIR="${PROUT_DIST_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/copy_if_exists.cmake"
    COMMAND ${CMAKE_COMMAND}
            -DSRC="${LITERT_OPENCL_ACCELERATOR_DLL}"
            -DDST_DIR="${PROUT_DIST_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/copy_if_exists.cmake"
    COMMAND ${CMAKE_COMMAND}
            -DSRC="${LITERT_GPU_ACCELERATOR_DLL}"
            -DDST_DIR="${PROUT_DIST_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/copy_if_exists.cmake"
    COMMENT "Staging prout.exe + CPU/GPU LiteRT runtime DLLs into dist/")
endif()

set(PROUT_CLANG_FORMAT_HINTS)
if(WIN32)
  list(APPEND PROUT_CLANG_FORMAT_HINTS
       "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/bin"
       "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin")
endif()

find_program(PROUT_CLANG_FORMAT
  NAMES clang-format clang-format.exe
  HINTS ${PROUT_CLANG_FORMAT_HINTS})

if(NOT PROUT_CLANG_FORMAT)
  message(FATAL_ERROR "clang-format was not found. Install the Visual Studio LLVM tools or add clang-format to PATH.")
endif()

file(GLOB_RECURSE PROUT_FORMAT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_SOURCE_DIR}/src/*.cc"
  "${CMAKE_SOURCE_DIR}/src/*.h")

add_custom_target(format
  COMMAND "${PROUT_CLANG_FORMAT}" -i ${PROUT_FORMAT_SOURCES}
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMENT "Formatting Prout C++ sources with clang-format")

add_executable(prout_hardening_tests
  tests/hardening_tests.cc
  src/daemon/lease.cc
  src/ipc/ipc.cc
  src/vault/crypto.cc
  src/common/paths.cc
  src/common/secure_mem.cc
  third_party/monocypher/monocypher.c)

target_include_directories(prout_hardening_tests PRIVATE
  "${CMAKE_SOURCE_DIR}/src"
  "${CMAKE_SOURCE_DIR}/third_party/monocypher")

target_link_libraries(prout_hardening_tests PRIVATE
  absl::status
  absl::statusor)

if(WIN32)
  target_link_libraries(prout_hardening_tests PRIVATE ws2_32 bcrypt advapi32)
  target_compile_definitions(prout_hardening_tests PRIVATE _WIN32_WINNT=0x0600 NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

enable_testing()
add_test(NAME prout_hardening_tests COMMAND prout_hardening_tests)
add_test(NAME prout_clang_format
  COMMAND "${PROUT_CLANG_FORMAT}" --dry-run --Werror ${PROUT_FORMAT_SOURCES})

add_test(NAME prout_cli_flows
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass
          -File ${CMAKE_SOURCE_DIR}/tests/scripts/cli_flows.ps1
          -ProutExe $<TARGET_FILE:prout>
          -DistDir ${PROUT_DIST_DIR})


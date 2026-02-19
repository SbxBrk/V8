#!/bin/bash

set -eu

readonly ROOT="/work"
readonly V8_BUILD_ROOT=${ROOT}/v8-build
readonly LLVM_PASS_ROOT=${V8_BUILD_ROOT}/heap_sandbox_fuzzing_pass
readonly AFLPP_ROOT="${ROOT}/AFLplusplus"
readonly RT_LIB_PATH="${ROOT}/fuzzer/target/release/libv8fuzz_runtime.so"
readonly RT_LIB_FOLDER="$(dirname $RT_LIB_PATH)"
readonly LLVM_PREFIX="/usr"
readonly GN_ARGS="
is_debug = false
dcheck_always_on = false
symbol_level=2
use_dwarf5=true
enable_frame_pointers=true
v8_enable_backtrace=true
clang_use_chrome_plugins = false
custom_toolchain = \"//build/toolchain/linux/unbundle:default\"
host_toolchain = \"//build/toolchain/linux/unbundle:default\"
is_asan = true
v8_enable_sandbox = true
v8_enable_memory_corruption_api = true
v8_static_library = true
v8_fuzzilli = false
target_cpu = \"x64\"
treat_warnings_as_errors = false
"
readonly OUT_DIR=out/fuzzing-build


if [ -t 1 ]; then
    text_red=$(tput setaf 1)    # Red
    text_green=$(tput setaf 2)  # Green
    text_bold=$(tput bold)      # Bold
    text_reset=$(tput sgr0)     # Reset your text
else
    text_red=""
    text_green=""
    text_bold=""
    text_reset=""
fi

function err {
    echo "${text_bold}${text_red}[!] ${1}${text_reset}"
}

function ok {
    echo "${text_bold}${text_green}[+] ${1}${text_reset}"
}

ok "Buildind the LLVM pass..."
pushd $LLVM_PASS_ROOT
make
popd

if [[ ! -f "$RT_LIB_PATH" ]]; then
    err "Failed to find runtime library at $RT_LIB_PATH."
    err "Please build the fuzzer including the runtime (cargo build -r) before building V8."
    exit 1
fi
# shellcheck disable=SC2155
export LD_LIBRARY_PATH="$(dirname $RT_LIB_PATH)"
ok "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"

export CC=$AFLPP_ROOT/afl-clang-fast
if [[ ! -f "$CC" ]]; then
    err "Failed to find afl-clang-fast at $CC. Please build AFL++ before building V8".
    exit 1
fi
export CXX=$AFLPP_ROOT/afl-clang-fast++
export LD="$CC"
export LLVM_CONFIG="$LLVM_PREFIX/bin/llvm-config"
export AR="$LLVM_PREFIX/bin/llvm-ar"
export NM="$LLVM_PREFIX/bin/llvm-nm"

# -DSBXBRK_NO_INSTRUMENT_ASSEMBLER may be removed to instrument loads in the JITed code as well.
export CFLAGS="-DSBXBRK_NO_INSTRUMENT_ASSEMBLER -Wno-unknown-warning-option -Wno-error -fuse-ld=lld -fpass-plugin=$LLVM_PASS_ROOT/heap_sandbox_fuzzing_pass.so -L${RT_LIB_FOLDER}"
export CXXFLAGS="$CFLAGS"
# The generate_bytecode_builtins_list target sets --no-allow-shlib-undefined, but our runtime is dynamically linked against
# glibc, thus building would fail without --allow-shlib-undefined.
export LDFLAGS="-Wl,--allow-shlib-undefined -L${RT_LIB_FOLDER} -lv8fuzz_runtime"

ok "Pulling dependencies"
gclient sync --reset

# ok "Removing unsupported LLVM flags"
# pushd build
# git apply ../build.patch
# popd

ok "Build args:$GN_ARGS"
ok "Build result will be stored at $OUT_DIR"

if [[ ! -d "$OUT_DIR" ]]; then
    gn gen $OUT_DIR --args="
    $GN_ARGS
    "
fi

if ! ninja -C "$OUT_DIR" d8; then
    err "Build failed. Check the logging output and/or delete the output directory $OUT_DIR"
fi

ninja -C "./$OUT_DIR" -t compdb cxx cc d8 > compile_commands.json
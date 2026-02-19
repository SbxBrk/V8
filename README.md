# V8 (SbxBrk)

This repository contains a fork of V8 used by [SbxBrk](https://github.com/SbxBrk/SbxBrk) for heap sandbox fuzzing. It includes a custom LLVM pass and build configuration for compiling V8 with fault-injection instrumentation.

## Heap Sandbox Fuzzing Pass

The [`heap_sandbox_fuzzing_pass`](./heap_sandbox_fuzzing_pass/) is a custom LLVM pass that instruments all memory loads whose target may reside inside the V8 heap sandbox. For each such load, the pass inserts a call to `__fuzzer_before_heap_sandbox_load`, which allows the fuzzer runtime to inject faults (via bitmasks) before the loaded data reaches trusted code.

Loads from local variables and globals are statically filtered out to reduce overhead. The pass is compiled as a shared object and loaded into the compilation pipeline via `-fpass-plugin`.

## Building

V8 must be compiled inside the Docker environment provided by the [main repository](https://github.com/SbxBrk/SbxBrk). AFL++ and the fuzzer runtime must be built first.

```sh
cd /work/v8-build
./build.sh
```

The [`build.sh`](./build.sh) script handles building the LLVM pass, pulling V8 dependencies, and compiling V8 with ASan, sandbox support, and the fuzzing instrumentation. The resulting `d8` shell is placed at `out/fuzzing-build/d8`.

For full setup instructions, see the [main repository](https://github.com/SbxBrk/SbxBrk).

#include <stdlib.h>
#include <cstddef>

__attribute__((visibility("default")))
extern "C" void __fuzzer_get_heap_snapshot() {}

__attribute__((visibility("default")))
extern "C" void __fuzzer_get_attributes() {}

__attribute__((visibility("default")))
extern "C" void __fuzzer_get_all_heap_objects() {}
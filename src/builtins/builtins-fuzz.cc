#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stack>

#include "src/api/api-inl.h"
#include "src/builtins/builtins-utils-inl.h"
#include "src/builtins/builtins.h"
#include "src/debug/interface-types.h"
#include "src/execution/isolate.h"
#include "src/logging/counters.h"
#include "src/heap/combined-heap.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/objects/keys.h"
#include "src/sandbox/sandbox.h"
#include "src/utils/utils.h"
#include "v8-profiler.h"

extern "C" void __fuzzer_had_control_builtin(void);
extern "C" void __fuzzer_injection_point_builtin(uint16_t);
extern "C" void __fuzzer_before_heap_sandbox_load(uint64_t, uintptr_t, size_t);
extern "C" void __fuzzer_set_fault_injection_enabled(bool);

class BufferStream : public v8::OutputStream {
public:
    BufferStream() : buffer_(nullptr), size_(0), capacity_(0) {}

    ~BufferStream() override {
        if (buffer_) {
            //free(buffer_);
        }
    }

    WriteResult WriteAsciiChunk(char* data, int size) override {
        EnsureCapacity(size_ + size);
        memcpy(buffer_ + size_, data, size);
        size_ += size;
        return kContinue;
    }

    void EndOfStream() override {}

    char* GetBuffer() const { return buffer_; }
    size_t GetSize() const { return size_; }

private:
    char* buffer_;
    size_t size_;
    size_t capacity_;

    void EnsureCapacity(size_t required) {
        if (required > capacity_) {
            capacity_ = required * 2;  // Double the capacity
            buffer_ = static_cast<char*>(realloc(buffer_, capacity_));
            if (!buffer_) {
                std::cerr << "Out of memory while reallocating buffer\n";
                std::exit(EXIT_FAILURE);
            }
        }
    }
};

__attribute__((visibility("default")))
extern "C" void __fuzzer_get_heap_snapshot(void **buffer, size_t *buffer_size) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::HeapProfiler* heap_profiler = isolate->GetHeapProfiler();
    //heap_profiler->StartTrackingHeapObjects(true);

    const v8::HeapSnapshot* snapshot = heap_profiler->TakeHeapSnapshot();

    BufferStream buffer_stream;
    snapshot->Serialize(&buffer_stream);

    *buffer = buffer_stream.GetBuffer();
    *buffer_size = buffer_stream.GetSize();
}

bool fuzzer_crash_functions_enabled() {
  if (getenv("FUZZER_CRASH_FUNCTIONS") != nullptr) {
    return true;
  } else {
    fprintf(stderr, "Set the FUZZER_CRASH_FUNCTIONS environment variable to enable the crash functions\n");
    return false;
  }
}

namespace v8 {

namespace internal {

BUILTIN(GlobalFuzzerInjectionPoint) {
    int const argc = args.length() - 1;

    if (argc != 1) {
        return isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kInvalidArgument,
            isolate->factory()->NewStringFromAsciiChecked("Expected 1 argument (u32)")));
    }

    Handle<Object> id_obj;
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
        isolate, id_obj, Object::ToNumber(isolate, args.at(1)));
    uint32_t id = static_cast<uint32_t>(Object::NumberValue(*id_obj));

    __fuzzer_injection_point_builtin(id);
    //func_t fp =  __fuzzer_injection_point_builtin(id);
    //fp();

    return ReadOnlyRoots(isolate).undefined_value();
}


}  // namespace internal
}  // namespace v8
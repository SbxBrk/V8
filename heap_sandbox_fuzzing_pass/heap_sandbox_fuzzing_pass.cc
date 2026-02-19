#include <assert.h>
#include <cstddef>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassInstrumentation.h>
#include <llvm/IR/Use.h>
#include <llvm/IR/Value.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <utility>
#include <vector>

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Demangle/Demangle.h"

using namespace llvm;

namespace {

class HeapSandboxFuzzingPass : public PassInfoMixin<HeapSandboxFuzzingPass> {
  private:
  public:
    bool instrumentLoads(Module &F);
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

} // namespace

PreservedAnalyses HeapSandboxFuzzingPass::run(Module &M,
                                              ModuleAnalysisManager &MAM) {
    bool modified = false;

    dbgs() << "[+] Running heap sandbox fuzzing llvm pass\n";

    modified |= instrumentLoads(M);

    if (modified) {
        return PreservedAnalyses::none();
    } else {
        return PreservedAnalyses::all();
    }
}

/*
Split a string containing multiple comma-separated keywords
and return the set of these keywords
*/
std::vector<std::string> split_string(std::string s, char delim) {
    size_t pos_start = 0, pos_end;
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delim, pos_start)) != std::string::npos) {
        token = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + 1;
        res.push_back(token);
    }

    res.push_back(s.substr(pos_start));
    return res;
}

/*
Check if an environment variable is set.
*/
bool env_var_set(const char *env_var) {
    const char *envp = std::getenv(env_var);
    if (envp)
        return true;
    return false;
}

/*
Convert environment variable content to a set.
Expects comma-separated list of values in the env var.
*/
std::vector<std::string> parse_env_var_list(const char *env_var) {
    const char *envp = std::getenv(env_var);
    if (!envp)
        return std::vector<std::string>();
    return split_string(std::string(envp), /* delim = */ ',');
}

/*
Extract integer specified in environment variable.
*/
uint64_t parse_env_var_int(const char *env_var, uint64_t default_val) {
    const char *envp = std::getenv(env_var);
    if (!envp)
        return default_val;
    uint64_t val = static_cast<uint64_t>(std::stoll(envp));
    return val;
}

// Check if the value `ptr` was loaded from a local or global variable.
bool isLocalOrGlobal(Value *ptr, size_t stack_depth) {
    if (stack_depth > 16)
        return false;

    if (AllocaInst *allocaInst = dyn_cast<AllocaInst>(ptr)) {
        // AllocaInst is used for stack allocations.
        return true;
    } else if (GlobalVariable *globalVar = dyn_cast<GlobalVariable>(ptr)) {
        // GlobalVariable :)
        return true;
    } else if (GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(ptr)) {
        // Recursively check the pointer operand of the GEP instruction
        return isLocalOrGlobal(gepInst->getPointerOperand(), ++stack_depth);
    } else if (LoadInst *loadInst = dyn_cast<LoadInst>(ptr)) {
        // Recursively check the pointer operand of the load instruction
        //return isLocalOrGlobal(loadInst->getPointerOperand(), ++stack_depth);
        return false;
    } else if (SelectInst *selectInst = dyn_cast<SelectInst>(ptr)) {
        // Recursively check both possible values in the Select instruction
        return isLocalOrGlobal(selectInst->getTrueValue(), ++stack_depth) &&
               isLocalOrGlobal(selectInst->getFalseValue(), ++stack_depth);
    } else if (PHINode *phiNode = dyn_cast<PHINode>(ptr)) {
        // Recursively check all incoming values to the PHI node
        // FIXME: This probably causes endless recursion? Currently this is avoided by using `stack_depth`.
        for (unsigned i = 0; i < phiNode->getNumIncomingValues(); ++i) {
            if (!isLocalOrGlobal(phiNode->getIncomingValue(i), ++stack_depth)) {
                // If ther is any case where the value is not local or global, we must
                // return false.
                return false;
            }
        }
        // For all inputs of the phi node isLocalOrGlobal returned true, thus this is
        // in all cases a local or global variable.
        return true;
    }

    // While this may still be a local or global, we were not able to prove it thus we assume it is not.
    return false;
}

bool shouldLoadBeInstrumented(LoadInst *loadInst) {
    Value *ptrOperand = loadInst->getPointerOperand();
    size_t stack_depth = 0;
    return !isLocalOrGlobal(ptrOperand, stack_depth);
}

bool function_should_be_skipped(Function &f) {
    std::string mangledName = f.getName().str();
    std::string demangledName = llvm::demangle(mangledName.c_str());

    if (f.isIntrinsic() || f.empty()) {
        return true;
    }

    // We dont want to instrument the calles to our own builtins.
    if (demangledName.find("GlobalInjectionPoint") != std::string::npos || 
        demangledName.find("GlobalFuzzerHadControl") != std::string::npos) {
        return true;
    }

    return false;
}

uint64_t generateRandomU64() {
    static std::mt19937_64 rng(std::random_device{}()); // Seed with random device
    return rng();
}


bool HeapSandboxFuzzingPass::instrumentLoads(Module &M) {
    IntegerType *int64ty = IntegerType::getInt64Ty(M.getContext());
    const DataLayout &dataLayout = M.getDataLayout();

    //return false;

    size_t module_intrumented_loads = 0;
    size_t module_filtered_loads = 0;
    auto before_load_cb_fn = M.getOrInsertFunction(
        "__fuzzer_before_heap_sandbox_load", FunctionType::getVoidTy(M.getContext()),
        int64ty, int64ty, int64ty);
    if (auto *F = dyn_cast<Function>(before_load_cb_fn.getCallee())) {
        F->addFnAttr("memory", "argmem: readwrite");
    }

    for (auto &f : M.functions()) {
        size_t function_intrumented_loads = 0;
        size_t function_filtered_loads = 0;
        if (function_should_be_skipped(f)) {
            continue;
        }

        std::vector<LoadInst *> load_instructions;
        Constant *sandbox_base_addr =
            M.getOrInsertGlobal("__fuzzer_heap_sandbox_base", int64ty);
        IRBuilder<> irb(&*f.getEntryBlock().getFirstInsertionPt());
        auto sandbox_base_val = irb.CreateLoad(int64ty, sandbox_base_addr);



        for (auto &BB : f) {
            for (auto &I : BB) {
                if (LoadInst *load = dyn_cast<LoadInst>(&I)) {
                    load_instructions.push_back(load);
                }
            }
        }

        for (auto load_ins : load_instructions) {
            if (!shouldLoadBeInstrumented(load_ins)) {
                function_filtered_loads += 1;
                module_filtered_loads += 1;
                continue;
            }

            // Generate ID for this load.
            uint64_t load_id = generateRandomU64();


            function_intrumented_loads += 1;
            module_intrumented_loads += 1;

            auto load_op = load_ins->getPointerOperand();
            auto load_type = load_ins->getType();
            IRBuilder<> irb(&*load_ins);

            auto load_ptr_as_int = irb.CreatePtrToInt(load_op, int64ty);
            auto offset = irb.CreateSub(load_ptr_as_int, sandbox_base_val);

            // check if ptr points into sandbox
            // Sandbox size is 1TB (i.e., 1 << 40 bytes)
            auto is_in_sandbox = irb.CreateICmpULE(
                offset, ConstantInt::get(int64ty, 1ull << 40));

            auto if_sandbox_block =
                SplitBlockAndInsertIfThen(is_in_sandbox, load_ins, false);
            irb.SetInsertPoint(if_sandbox_block);

            auto load_size = dataLayout.getTypeStoreSize(load_type);
            auto call = irb.CreateCall(before_load_cb_fn, { ConstantInt::get(int64ty, load_id), load_ptr_as_int,
                                     ConstantInt::get(int64ty, load_size) });
            if (auto *dbg = load_ins->getMetadata("dbg")) {
                call->setMetadata("dbg", dbg);
            }
        }

        // dbgs() << "[+] Instrumented " << function_intrumented_loads
        //        << " loads in function" << f.getName() << "\n";
    }

    dbgs() << "[+] Instrumented " << module_intrumented_loads << " loads (" << module_filtered_loads << " filtered) in module"
           << M.getName() << "\n";
    return module_intrumented_loads > 0;
}


bool shouldStoreBeInstrumented(StoreInst *store) {
    Value *ptrOperand = store->getPointerOperand();
    size_t stack_depth = 0;
    return !isLocalOrGlobal(ptrOperand, stack_depth);
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "heap-sandbox-fuzzing-pass", "v0.1",
            [](PassBuilder &PB) {
#if LLVM_VERSION_MAJOR == 13
                using OptimizationLevel =
                    typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 16
                PB.registerOptimizerLastEPCallback(
#else
                PB.registerOptimizerLastEPCallback(
#endif
#if LLVM_VERSION_MAJOR >= 21
                    [](ModulePassManager &MPM, OptimizationLevel OL,
                       ThinOrFullLTOPhase ToFLTO) {
#else
                    [](ModulePassManager &MPM, OptimizationLevel OL) {
#endif
                        MPM.addPass(HeapSandboxFuzzingPass());
                    });
            }
    };
}

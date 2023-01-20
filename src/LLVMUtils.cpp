/**
 * @file LLVMUtils.hpp
 * @author Johannes Blaser (j.blaser@vu.nl)
 * @brief Header file for a custom LLVM utility functions library
 * @version 0.1
 * @date 2023-01-14
 *
 * @copyright Copyright (c) 2023 (GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007)
 *
 */

#include "LLVMUtils.hpp"

#include <cxxabi.h>

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/MemoryBuiltins.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Statepoint.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>

#include <cstdint>
#include <limits>
#include <system_error>
#include <unordered_set>

namespace llvm_utils {

using namespace std;
using namespace llvm;
inline static const unordered_set<string> KnownMemFuncs = {"malloc",
                                                           "calloc",
                                                           "realloc",
                                                           "reallocarray",
                                                           "memalign",
                                                           "aligned_alloc",
                                                           "valloc",
                                                           "pvalloc",
                                                           "posix_memalign",
                                                           "mmap",
                                                           "mmap64",
                                                           "free",
                                                           "free_sized",
                                                           "free_aligned_size",
                                                           "munmap",
                                                           "strdup",
                                                           "strndup",
                                                           "asprintf",
                                                           "aswprintf",
                                                           "vasprintf",
                                                           "vaswprintf",
                                                           "getline",
                                                           "getwline",
                                                           "getdelim",
                                                           "getwdelim",
                                                           "allocate_at_least",
                                                           "construct_at",
                                                           "destroy_at",
                                                           "destroy",
                                                           "destroy_n",
                                                           "new",
                                                           "new[]",
                                                           "delete",
                                                           "delete[]",
                                                           "tempnam",
                                                           "get_current_dir_name",
                                                           "realpath"};

// Print LLVM value to string object
auto str(const Value *V) -> string {
    assert(V);
    string             S;
    raw_string_ostream RSO(S);
    if (V) { V->print(RSO, true); }
    return S;
}
auto str(const Type *T) -> string {
    assert(T);
    string             S;
    raw_string_ostream RSO(S);
    if (T) { T->print(RSO, true); }
    return S;
}

// Convert boolean to readable string
auto boolToStr(bool B) -> string { return B ? "true" : "false"; }

// True if the argument is known NOT to be defined by the user (i.e. known not in file in /home/*)
auto isSysDef(const Instruction *I) -> bool {
    assert(I);
    auto *F      = I->getFunction();
    auto *Sub    = F ? F->getSubprogram() : nullptr;
    auto  SrcDir = Sub ? Sub->getDirectory() : "";
    return !SrcDir.startswith_insensitive("/home");
}

// Check if address marked dead is certain to never become alive again after lifetime end marker
auto staysDead(IntrinsicInst *II) -> bool {
    assert(II);
    if (!isLifetimeEnd(II)) return false;    // If not lifetime end marker; return false

    // Get information about lifetime end marker's location in function
    DominatorTree                 DTree(*II->getFunction());
    LoopInfo                      LInfo(DTree);
    SmallPtrSet<Value *, 4>       Visited;
    SmallVector<Instruction *, 4> Worklist;

    // Add to worklist if non-null, not the input lifetime marker, and not visited yet
    auto AddWork = [&](Instruction *I) {
        assert(I);
        if (I != II && Visited.insert(I).second) Worklist.push_back(I);
    };

    // Get all alloca instructions for lifetime marker's address & add to worklist
    for (auto *AI : getAllocas(II)) AddWork(AI);

    // For all insts in worklist, check if they use the same address as the starting marker, AND
    // could potentially be reachable from the starting marker, and are a lifetime start marker
    while (!Worklist.empty()) {
        auto *I = Worklist.pop_back_val();
        assert(I && Visited.contains(I));
        if (I == II) continue;    // Skip starting lifetime marker

        // If I is lifetime start & reachable from initial marker, addr COULD be alive again
        if (isLifetimeStart(I) && isPotentiallyReachable(I, II, nullptr, &DTree, &LInfo)) {
            return false;    // Could become alive again; doesn't stay dead
        }

        // For all users of the instruction, add them to the worklist (this strips casts and such)
        for (auto *U : I->users()) {
            assert(U);
            if (isa<Instruction>(U)) AddWork(cast<Instruction>(U));
        }
    }
    return true;    // No lifetime start marker uses II after II; addr stays dead until func ret
}

// Get source row and column location if known (needs debug symbols); {-1, -1} if unknown location
auto getSrcLoc(const Instruction *I) -> pair<int64_t, int64_t> {
    assert(I);
    if (auto *DILoc = I->getDebugLoc().get()) {
        while (DILoc->getInlinedAt()) DILoc = DILoc->getInlinedAt();
        return {DILoc->getLine(), DILoc->getColumn()};
    }
    return {-1, -1};    // Unknown location
}

// Get string with the name of the function & the file where the function is defined
auto getSrcLocStr(const Function *F) -> string {
    assert(F);
    auto *Sub = F->getSubprogram();
    if (!Sub) return "unknown_file";

    auto File     = Sub->getFilename().str();        // Get name of source file
    auto FuncName = demangle(F->getName().str());    // Get demangled if applicable
    return FuncName + "() (file: " + File + ")";
}

// Functions for determining whether given type or value is, contains, or uses a var-arg object
auto isVarArgList(const Type *T) -> bool {
    assert(T);
    auto *STy = dyn_cast<StructType>(T);
    if (!STy) return false;                                   // LLVM va_list is always struct
    if (STy->isLiteral()) return false;                       // Literal structs can't have name
    return STy->getName().contains_insensitive("va_list");    // Check if named va_list struct
}
auto isOrHasVarArgList(const Type *T) -> bool {
    assert(T);
    SmallPtrSet<const Type *, 4> Visited;
    SmallVector<const Type *, 4> Worklist;
    auto                         AddWork = [&](const Type *Ty) -> void {
        assert(Ty);
        if (Visited.insert(Ty).second) Worklist.push_back(Ty);
    };

    // Check if the type itself, or any of its contained subtypes recursively, are va_list structs
    AddWork(T);
    while (!Worklist.empty()) {
        auto *Ty = Worklist.pop_back_val();
        assert(Ty && Visited.contains(Ty));
        if (isVarArgList(Ty)) return true;    // Ty is va_list struct
        for (auto *SubTy : Ty->subtypes()) {
            assert(SubTy);
            AddWork(SubTy);    // Explore all subtypes
        }
    }
    return false;    // No matches to va_list struct found
}

// Create/get function type for return type and optional list of argument types
auto getFnTy(Type *RetTy) -> FunctionType * {
    assert(RetTy);
    return FunctionType::get(RetTy, false);
}
auto getFnTy(Type *RetTy, vector<Type *> ArgTys) -> FunctionType * {
    assert(RetTy);
    return FunctionType::get(RetTy, ArgTys, false);
}

// Determine if function/call/instruction is definitely memory safe (unsafe if uncertain)
auto possibleUnsafe(const CallBase *CB) -> bool {
    assert(CB);
    if (CB->hasRetAttr(Attribute::NoAlias)) return true;
    if (CB->hasFnAttr(Attribute::NoAlias)) return true;
    if (!CB->hasRetAttr(Attribute::NoFree)) return true;
    if (!CB->hasFnAttr(Attribute::NoFree)) return true;
    if (!CB->doesNotAccessMemory()) return true;
    if (!CB->returnDoesNotAlias()) return true;
    if (CB->mayReadOrWriteMemory()) return true;
    if (CB->mayHaveSideEffects()) return true;
    if (CB->isIndirectCall()) return true;
    if (CB->mayThrow()) return true;
    return false;
}
auto possibleUnsafe(Function *F, FunctionAnalysisManager *FAM) -> bool {
    assert(F);
    if (F->hasFnAttribute(Attribute::InaccessibleMemOnly)) return true;
    if (F->hasFnAttribute(Attribute::ReadNone)) return true;
    if (F->hasFnAttribute(Attribute::NoAlias)) return true;
    if (!F->hasFnAttribute(Attribute::NoFree)) return true;
    if (!F->callsFunctionThatReturnsTwice()) return true;
    if (KnownMemFuncs.contains(demangle(F->getName().str()))) return true;

    // Run library info analysis on function/target/module if FAM is provided
    if (FAM) {
        auto   &TLI = FAM->getResult<TargetLibraryAnalysis>(*F);
        LibFunc TLIF;
        if (isAllocationFn(F, &TLI)) return true;
        if (TLI.getLibFunc(*F, TLIF) && TLI.has(TLIF) && isLibFreeFunction(F, TLIF)) return true;
    }
    return false;
}

// Get underlying called function even if function is some sort of statepoint instruction
auto getCalledFn(const CallBase *CB) -> Function * {
    assert(CB);
    if (auto *GCSP = dyn_cast<GCStatepointInst>(CB)) {
        auto *F = GCSP->getActualCalledFunction();
        return F ? F : CB->getCalledFunction();
    }
    return CB->getCalledFunction();
}

// Checker functions for determining if the given instruction is a lifetime end/start marker
auto isLifetimeStart(const Instruction *I) -> bool {
    assert(I);
    if (!isa<IntrinsicInst>(I)) return false;
    return cast<IntrinsicInst>(I)->getIntrinsicID() == Intrinsic::lifetime_start;
}
auto isLifetimeEnd(const Instruction *I) -> bool {
    assert(I);
    if (!isa<IntrinsicInst>(I)) return false;
    return cast<IntrinsicInst>(I)->getIntrinsicID() == Intrinsic::lifetime_end;
}

// Get set of all alloca instructions that could have allocated the lifetime marker's address
auto getAllocas(const IntrinsicInst *II) -> set<AllocaInst *> {
    assert(II);
    if (!II->isLifetimeStartOrEnd()) return {};    // Only check valid lifetime markers

    auto                   *Addr = II->getOperand(1);    // Marked address is in operand 1
    SmallVector<Value *, 4> SrcObjs;                     // All underlying objects
    set<AllocaInst *>       Allocas;                     // Only allocas from underlying objs
    getUnderlyingObjectsForCodeGen(Addr, SrcObjs);       // Get underlying objs (also non-allocas)

    // Filter out all non-alloca instruction objects & create set with only alloca insts
    for (auto *Obj : SrcObjs) {
        assert(Obj);
        if (auto *AI = dyn_cast<AllocaInst>(Obj)) Allocas.insert(AI);    // Add all allocas
    }
    return Allocas;
}

// Dump LLVM module IR to file
auto dumpIR(const llvm::Module *M, std::string File) -> void {
    assert(M);
    error_code     EC;
    raw_fd_ostream IRDumpFile(File, EC);    // Truncates existing
    if (IRDumpFile.has_error()) return;
    M->print(IRDumpFile, nullptr, false, true);    // Dump with debug info
    IRDumpFile.close();
}

// Run the the default O0, O1, O2, or O3 optimisation pass pipelines on the given module
auto optimiseModule(Module *M, PassBuilder::OptimizationLevel OptLevel) -> PreservedAnalyses {
    assert(M);
    LoopAnalysisManager     LAM;
    FunctionAnalysisManager FAM;
    CGSCCAnalysisManager    CGAM;
    ModuleAnalysisManager   MAM;
    PassBuilder             PB;
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
    return PB.buildPerModuleDefaultPipeline(OptLevel).run(*M, MAM);
}

};    // namespace llvm_utils

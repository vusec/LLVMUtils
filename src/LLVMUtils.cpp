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
template <typename T>
auto str(T *V) -> string {
    string             S;
    raw_string_ostream RSO(S);
    if (V) { V->print(RSO, true); }
    return S;
}
template <typename T>
auto str(T &V) -> string {
    string             S;
    raw_string_ostream RSO(S);
    V.print(RSO, true);
    return S;
}

// Convert boolean to readable string
auto boolToStr(bool B) -> string { return B ? "true" : "false"; }

// True if arg has unknown definition location or in known user-file (i.e. file in /home/*)
auto isSysDef(Value *V) -> bool {
    if (!V) return false;
    if (isa<Function>(V)) return isSysDef(cast<Function>(V));
    if (isa<Instruction>(V)) return isSysDef(cast<Instruction>(V));
    return true;    // Unknown
}
auto isSysDef(Function *F) -> bool {
    if (!F) return false;
    auto *Sub = F->getSubprogram();
    return Sub ? !Sub->getDirectory().startswith_insensitive("/home") : true;    // True if unknown
}
auto isSysDef(Instruction *I) -> bool {
    if (!I) return false;
    return (isSysDef(I->getFunction()));
}

// Check if address marked dead is certain to never become alive again after lifetime end marker
auto staysDead(IntrinsicInst *II) -> bool {
    if (!II) return false;
    if (!isLifetimeEnd(II)) return false;    // If not lifetime end marker; return false

    // Get information about lifetime end marker's location in function
    DominatorTree                 DTree(*II->getFunction());
    LoopInfo                      LInfo(DTree);
    SmallPtrSet<Value *, 4>       Visited;
    SmallVector<Instruction *, 4> Worklist;

    // Add to worklist if non-null, not the input lifetime marker, and not visited yet
    auto AddWork = [&](Instruction *I) {
        if (I && I != II && Visited.insert(I).second) Worklist.push_back(I);
    };

    // Get all alloca instructions for lifetime marker's address & add to worklist
    for (auto *AI : getAllocas(II)) AddWork(AI);

    // For all insts in worklist, check if they use the same address as the starting marker, AND
    // could potentially be reachable from the starting marker, and are a lifetime start marker
    while (!Worklist.empty()) {
        auto *I = Worklist.pop_back_val();
        if (!I || I == II) continue;    // Skip starting lifetime marker

        // If I is lifetime start & reachable from initial marker, addr COULD be alive again
        if (isLifetimeStart(I) && isPotentiallyReachable(I, II, nullptr, &DTree, &LInfo)) {
            return false;    // Could become alive again; doesn't stay dead
        }

        // For all users of the instruction, add them to the worklist (this strips casts and such)
        for (auto *U : I->users()) {
            if (isa<Instruction>(U)) AddWork(cast<Instruction>(U));
        }
    }
    return true;    // No lifetime start marker uses II after II; addr stays dead until func ret
}

// Get source row and column location if known (needs debug symbols); {-1, -1} if unknown location
auto getSrcLoc(Instruction *I) -> pair<int64_t, int64_t> {
    if (!I) return {INT64_MIN, INT64_MIN};

    if (auto *DILoc = I->getDebugLoc().get()) {
        while (DILoc->getInlinedAt()) DILoc = DILoc->getInlinedAt();
        return {DILoc->getLine(), DILoc->getColumn()};
    }
    return {-1, -1};    // Unknown location
}

// Get string with the name of the function & the file where the function is defined
auto getSrcLocStr(Function *F) -> string {
    if (!F) return string();

    auto *Sub = F->getSubprogram();
    if (!Sub) return "unknown_file";

    auto File     = Sub->getFilename().str();        // Get name of source file
    auto FuncName = demangle(F->getName().str());    // Get demangled if applicable
    return FuncName + "() (file: " + File + ")";
}

// Functions for determining whether given type or value is, contains, or uses a var-arg object
auto isVarArgList(Type *T) -> bool {
    if (!T) return false;
    if (T->isStructTy()) return false;                            // LLVM va_list is always struct
    if (cast<StructType>(T)->isLiteral()) return false;           // Literal structs can't have name
    return T->getStructName().contains_insensitive("va_list");    // Check if named va_list struct
}
auto isOrHasVarArgList(Type *T) -> bool {
    if (!T) return false;
    auto *VAListTy = StructType::getTypeByName(T->getContext(), "struct.__va_list_tag");
    if (!VAListTy) return false;    // No va_list struct in entire module; can early-exit

    SmallPtrSet<Type *, 4> Visited;
    SmallVector<Type *, 4> Worklist;
    auto                   AddWork = [&](Type *Ty) -> void {
        if (Ty && Visited.insert(Ty).second) Worklist.push_back(Ty);
    };

    // Check if the type itself, or any of its contained subtypes recursively, are va_list structs
    AddWork(T);
    while (!Worklist.empty()) {
        auto *Ty = Worklist.pop_back_val();
        if (!Ty) continue;
        if (Ty == VAListTy || isVarArgList(Ty)) return true;    // Ty is va_list struct
        for (auto *SubTy : Ty->subtypes()) {
            assert(SubTy);
            AddWork(SubTy);    // Explore all subtypes
        }
    }
    return false;    // No matches to va_list struct found
}
auto isOrHasVarArgList(Value *V) -> bool {
    if (!V) return false;
    return isOrHasVarArgList(V->getType());    // Check if type of V could be va_list
}

// Create/get function type for return type and optional list of argument types
auto getFnTy(Type *RetTy) -> FunctionType * {
    if (!RetTy) return nullptr;
    return FunctionType::get(RetTy, false);
}
auto getFnTy(Type *RetTy, vector<Type *> ArgTys) -> FunctionType * {
    if (!RetTy) return nullptr;
    return FunctionType::get(RetTy, ArgTys, false);
}

// Determine if function/call/instruction is definitely memory safe (unsafe if uncertain)
auto guaranteedSafeCall(CallBase *CB) -> bool {
    if (!CB) return false;
    if (CB->hasRetAttr(Attribute::NoAlias)) return false;
    if (CB->hasFnAttr(Attribute::NoAlias)) return false;
    if (!CB->hasRetAttr(Attribute::NoFree)) return false;
    if (!CB->hasFnAttr(Attribute::NoFree)) return false;
    if (!CB->doesNotAccessMemory()) return false;
    if (!CB->returnDoesNotAlias()) return false;
    if (CB->mayReadOrWriteMemory()) return false;
    if (CB->mayHaveSideEffects()) return false;
    if (CB->isIndirectCall()) return false;
    if (CB->mayThrow()) return false;
    if (!isSafeToSpeculativelyExecute(CB)) return false;
    auto *Callee = getCalledFn(CB);
    return Callee ? guaranteedSafeFn(Callee) : false;
}
auto guaranteedSafeFn(Function *F) -> bool {
    if (!F) return false;
    if (F->hasFnAttribute(Attribute::InaccessibleMemOnly)) return false;
    if (F->hasFnAttribute(Attribute::ReadNone)) return false;
    if (F->hasFnAttribute(Attribute::NoAlias)) return false;
    if (!F->hasFnAttribute(Attribute::NoFree)) return false;
    if (!F->callsFunctionThatReturnsTwice()) return false;
    if (KnownMemFuncs.contains(demangle(F->getName().str()))) return false;
    return true;    // F doesn't seem to access any memory whatsoever
}
auto guaranteedSafeFn(llvm::FunctionAnalysisManager *FAM, llvm::Function *F) -> bool {
    if (!FAM || !F) return false;
    auto   *LInf = &FAM->getResult<TargetLibraryAnalysis>(*F);
    LibFunc LibF;
    if (isAllocationFn(F, LInf, true)) return false;
    if (LInf->getLibFunc(*F, LibF) && LInf->has(LibF) && isLibFreeFunction(F, LibF)) return false;
    return guaranteedSafeFn(F);
}

// Get underlying called function even if function is some sort of statepoint instruction
auto getCalledFn(CallBase *CB) -> Function * {
    if (!CB) return nullptr;
    if (auto *GCSP = dyn_cast<GCStatepointInst>(CB)) {
        auto *F = GCSP->getActualCalledFunction();
        return F ? F : CB->getCalledFunction();
    }
    return CB->getCalledFunction();
}

// Checker functions for determining if the given instruction is a lifetime end/start marker
auto isLifetimeStart(Instruction *I) -> bool {
    if (!I) return false;
    if (!isa<IntrinsicInst>(I)) return false;
    return cast<IntrinsicInst>(I)->getIntrinsicID() == Intrinsic::lifetime_start;
}
auto isLifetimeEnd(Instruction *I) -> bool {
    if (!I) return false;
    if (!isa<IntrinsicInst>(I)) return false;
    return cast<IntrinsicInst>(I)->getIntrinsicID() == Intrinsic::lifetime_end;
}

// Get set of all alloca instructions that could have allocated the lifetime marker's address
auto getAllocas(IntrinsicInst *II) -> set<AllocaInst *> {
    if (!II) return {};
    if (!II->isLifetimeStartOrEnd()) return {};    // Only check valid lifetime markers

    auto                   *Addr = II->getOperand(1);    // Marked address is in operand 1
    SmallVector<Value *, 4> SrcObjs;                     // All underlying objects
    set<AllocaInst *>       Allocas;                     // Only allocas from underlying objs
    getUnderlyingObjectsForCodeGen(Addr, SrcObjs);       // Get underlying objs (also non-allocas)

    // Filter out all non-alloca instruction objects & create set with only alloca insts
    for (auto *Obj : SrcObjs) {
        if (auto *AI = dyn_cast<AllocaInst>(Obj)) Allocas.insert(AI);    // Add all allocas
    }
    return Allocas;
}

// Add metadata to LLVM value iff the value's type takes metadata (global objects & instructions)
auto addMetadata(Value *V, const StringRef &Kind, MDNode *MD) -> bool {
    if (!V || !MD) return false;
    if (auto *I = dyn_cast<Instruction>(V)) {
        I->setMetadata(Kind, MD);
        return true;
    }
    if (auto *GO = dyn_cast<GlobalObject>(V)) {
        GO->setMetadata(Kind, MD);
        return true;
    }
    return false;    // Value didn't support metadata
}

// Take two types and add them in a new struct type holding both types
auto wrapTypes(Type *T1, Type *T2) -> Type * {
    if (!T1 || !T2) return nullptr;
    return StructType::get(T1->getContext(), {T1, T2}, false);
}

// Run the the default O0, O1, O2, or O3 optimisation pass pipelines on the given module
auto optimiseModule(Module *M, PassBuilder::OptimizationLevel OptLevel) -> PreservedAnalyses {
    if (!M) return PreservedAnalyses::all();
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

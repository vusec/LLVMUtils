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
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/DiagnosticInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Statepoint.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>

#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <unordered_set>

namespace llvm_utils
{

using namespace std;
using namespace llvm;
namespace fs = filesystem;

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
                                                           "realpath",
                                                           "longjmp",
                                                           "siglongjmp",
                                                           "strdup",
                                                           "strndup",
                                                           "wcsdup",
                                                           "wcsndup",
                                                           "mbsdup",
                                                           "mbsndup"};

// Truncate string to maximum length

static inline auto isNL(char C) -> bool { return C == '\n'; }

static inline auto trnc(string &S) -> string
{
    string Str(S);                                       // Create new string object
    replace_if(Str.begin( ), Str.end( ), isNL, '\t');    // Replace newlines with tabs
    return Str.substr(0, 128);                           // Return truncated NEW string
}

// Print LLVM value to string object
auto str(const llvm::Value *V) -> string
{
    try {
        string                   S;
        llvm::raw_string_ostream RSO(S);
        if (V) V->print(RSO, true);
        return trnc(S);
    } catch (...) {
        return "ERROR";
    }
}

auto str(const llvm::Type *T) -> string
{
    try {
        string                   S;
        llvm::raw_string_ostream RSO(S);
        if (T) T->print(RSO, true);
        return trnc(S);
    } catch (...) {
        return "ERROR";
    }
}

// Convert boolean to readable string
auto boolToStr(bool B) -> string { return B ? "true" : "false"; }

// True if the argument is known NOT to be defined by the user (i.e. known not in file in /home/*)
auto isSysDef(const Instruction *I) -> bool
{
    if (!I) throw invalid_argument("Null ptr argument!");
    auto *F      = I->getFunction( );
    auto *Sub    = F ? F->getSubprogram( ) : nullptr;
    auto  SrcDir = Sub ? Sub->getDirectory( ) : "";
    return !SrcDir.startswith_insensitive("/home");
}

// Check if address marked dead is certain to never become alive again after lifetime end marker
auto staysDead(IntrinsicInst *II) -> bool
{
    if (!II) throw invalid_argument("Null ptr argument!");
    if (!isLifetimeEnd(II)) return false;    // If not lifetime end marker; return false

    // Get information about lifetime end marker's location in function
    DominatorTree                 DTree(*II->getFunction( ));
    LoopInfo                      LInfo(DTree);
    SmallPtrSet<Value *, 4>       Visited;
    SmallVector<Instruction *, 4> Worklist;

    // Add to worklist if non-null, not the input lifetime marker, and not visited yet
    auto AddWork = [&](Instruction *I) {
        if (I && I != II && Visited.insert(I).second) Worklist.push_back(I);
    };

    // Get all alloca instructions for lifetime marker's address & add to worklist
    for (auto *AI: getAllocas(II)) AddWork(AI);

    // For all insts in worklist, check if they use the same address as the starting marker, AND
    // could potentially be reachable from the starting marker, and are a lifetime start marker
    while (!Worklist.empty( )) {
        auto *I = Worklist.pop_back_val( );
        if (!I || I == II) continue;    // Skip starting lifetime marker

        // If I is lifetime start & reachable from initial marker, addr COULD be alive again
        if (isLifetimeStart(I) && isPotentiallyReachable(I, II, nullptr, &DTree, &LInfo))
            return false;    // Could become alive again; doesn't stay dead

        // For all users of the instruction, add them to the worklist (this strips casts and such)
        for (auto *U: I->users( ))
            if (isa<Instruction>(U)) AddWork(cast<Instruction>(U));
    }
    return true;    // No lifetime start marker uses II after II; addr stays dead until func ret
}

// Determine whether the memory operand access is statically known to be fully in bounds & safe
auto isFullySafeAccess(ObjectSizeOffsetVisitor &ObjSizeVis, Value *Addr, uint64_t TySize) -> bool
{
    SizeOffsetType SizeOffset = ObjSizeVis.compute(Addr);
    if (!ObjSizeVis.bothKnown(SizeOffset)) return false;

    // Retrieve size & offset
    uint64_t Size   = SizeOffset.first.getZExtValue( );
    int64_t  Offset = SizeOffset.second.getSExtValue( );

    // Three checks are required to ensure safety:
    // . Offset >= 0  (since the offset is given from the base ptr)
    // . Size >= Offset  (unsigned)
    // . Size - Offset >= NeededSize  (unsigned)
    return Offset >= 0 && Size >= uint64_t(Offset) && Size - uint64_t(Offset) >= TySize / 8;
}

// Get fully inlined source location (walk inlined-at chain)
auto getFullyInlinedSrcLoc(const Instruction *I) -> DILocation *
{
    if (!I) throw invalid_argument("Null ptr argument!");
    auto *DILoc = I->getDebugLoc( ).get( );
    while (DILoc && DILoc->getInlinedAt( )) DILoc = DILoc->getInlinedAt( );
    return DILoc;
}

// Get source row and column location if known (needs debug symbols); {-1, -1} if unknown location
auto getSrcLoc(const Instruction *I) -> pair<int64_t, int64_t>
{
    if (!I) return {-7, -7};
    DiagnosticLocation Loc(I->getDebugLoc( ));
    if (!Loc.isValid( )) return {-8, -8};
    auto Row = Loc.getLine( ) != 0 ? (int64_t) Loc.getLine( ) : -9;
    auto Col = Loc.getColumn( ) != 0 ? (int64_t) Loc.getColumn( ) : -9;
    return {Row, Col};
}

// Get string with the name of the function & the file where the function is defined
auto getSrcLocStr(const Function *F, string ModID) -> string
{
    DiagnosticLocation Loc(F ? F->getSubprogram( ) : nullptr);
    auto               FuncName = F ? demangle(F->getName( ).str( )) : "unknown_function";
    auto               FileName = Loc.isValid( ) ? fs::path(Loc.getAbsolutePath( )).filename( ) : "unknown_file";
    return FuncName + ";;" + FileName.string( ) + ";;" + ModID;
}

// Create/get function type for return type and optional list of argument types
auto getFnTy(Type *RetTy) -> FunctionType *
{
    if (!RetTy) throw invalid_argument("Null ptr argument!");
    return FunctionType::get(RetTy, false);
}

auto getFnTy(Type *RetTy, vector<Type *> ArgTys) -> FunctionType *
{
    if (!RetTy) throw invalid_argument("Null ptr argument!");
    return FunctionType::get(RetTy, ArgTys, false);
}

// Determine if function/call/instruction is definitely memory safe (unsafe if uncertain)
auto possibleUnsafe(const CallBase *CB) -> bool
{
    if (!CB) throw invalid_argument("Null ptr argument!");
    if (CB->hasRetAttr(Attribute::NoAlias)) return true;
    if (CB->hasFnAttr(Attribute::NoAlias)) return true;
    if (!CB->hasRetAttr(Attribute::NoFree)) return true;
    if (!CB->hasFnAttr(Attribute::NoFree)) return true;
    if (!CB->doesNotAccessMemory( )) return true;
    if (!CB->returnDoesNotAlias( )) return true;
    if (CB->mayReadOrWriteMemory( )) return true;
    if (CB->mayHaveSideEffects( )) return true;
    if (CB->isIndirectCall( )) return true;
    if (CB->mayThrow( )) return true;
    return false;
}

auto possibleUnsafe(Function *F, FunctionAnalysisManager *FAM) -> bool
{
    if (!F) throw invalid_argument("Null ptr argument!");
    if (F->hasFnAttribute(Attribute::InaccessibleMemOnly)) return true;
    if (F->hasFnAttribute(Attribute::ReadNone)) return true;
    if (F->hasFnAttribute(Attribute::NoAlias)) return true;
    if (!F->hasFnAttribute(Attribute::NoFree)) return true;
    if (!F->callsFunctionThatReturnsTwice( )) return true;
    if (KnownMemFuncs.contains(demangle(F->getName( ).str( )))) return true;

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
auto getCalledFn(const CallBase *CB) -> Function *
{
    if (!CB) throw invalid_argument("Null ptr argument!");
    if (auto *GCSP = dyn_cast<GCStatepointInst>(CB)) {
        auto *F = GCSP->getActualCalledFunction( );
        return F ? F : CB->getCalledFunction( );
    }
    return CB->getCalledFunction( );
}

// Checker functions for determining if the given instruction is a lifetime end/start marker
auto isLifetimeStart(const Instruction *I) -> bool
{
    if (!I) throw invalid_argument("Null ptr argument!");
    if (!isa<IntrinsicInst>(I)) return false;
    return cast<IntrinsicInst>(I)->getIntrinsicID( ) == Intrinsic::lifetime_start;
}

auto isLifetimeEnd(const Instruction *I) -> bool
{
    if (!I) throw invalid_argument("Null ptr argument!");
    if (!isa<IntrinsicInst>(I)) return false;
    return cast<IntrinsicInst>(I)->getIntrinsicID( ) == Intrinsic::lifetime_end;
}

// Get set of all alloca instructions that could have allocated the lifetime marker's address
auto getAllocas(const IntrinsicInst *II) -> set<AllocaInst *>
{
    if (!II) throw invalid_argument("Null ptr argument!");
    if (!II->isLifetimeStartOrEnd( )) return { };        // Only check valid lifetime markers

    auto                   *Addr = II->getOperand(1);    // Marked address is in operand 1
    SmallVector<Value *, 4> SrcObjs;                     // All underlying objects
    set<AllocaInst *>       Allocas;                     // Only allocas from underlying objs
    getUnderlyingObjectsForCodeGen(Addr, SrcObjs);       // Get underlying objs (also non-allocas)

    // Filter out all non-alloca instruction objects & create set with only alloca insts
    for (auto *Obj: SrcObjs)
        if (auto *AI = dyn_cast<AllocaInst>(Obj)) Allocas.insert(AI);    // Add all allocas
    return Allocas;
}

// Dump LLVM module IR to file
auto dumpIR(const Module *M, string File) -> void
{
    if (!M) throw invalid_argument("Null ptr argument!");
    error_code     EC;
    raw_fd_ostream IRDumpFile(File, EC);    // Truncates existing
    if (IRDumpFile.has_error( )) return;
    M->print(IRDumpFile, nullptr);          // Dump with debug info
    IRDumpFile.close( );
}

// Get the global variable holding all class construtors (llvm.globals.ctors)
auto getGlobalCtorsVar(const Module &M) -> GlobalVariable *
{
    auto *GV = M.getGlobalVariable("llvm.global_ctors");
    if (!GV || !GV->hasUniqueInitializer( )) return nullptr;

    auto *CA = dyn_cast<ConstantArray>(GV->getInitializer( ));
    if (!CA) return nullptr;

    for (auto &V: CA->operands( )) {
        if (isa<ConstantAggregateZero>(V)) continue;

        auto *CS = cast<ConstantStruct>(V);
        if (isa<ConstantPointerNull>(CS->getOperand(1))) continue;

        // Can only handle global constructors with no arguments.
        auto *F = dyn_cast<Function>(CS->getOperand(1));
        if (!F || F->arg_size( ) != 0) return nullptr;
    }
    return GV;
}

// Parse the global variable holding all global ctors & return them as a vector
auto getGlobalCtors(GlobalVariable *GV) -> vector<pair<uint32_t, Function *>>
{
    auto                              *CA = cast<ConstantArray>(GV->getInitializer( ));
    vector<pair<uint32_t, Function *>> Result;
    Result.reserve(CA->getNumOperands( ));
    for (auto &V: CA->operands( )) {
        auto *CS = cast<ConstantStruct>(V);
        Result.emplace_back(cast<ConstantInt>(CS->getOperand(0))->getZExtValue( ),
                            dyn_cast<Function>(CS->getOperand(1)));
    }
    return Result;
}

// Run the the default O0, O1, O2, or O3 optimisation pass pipelines on the given module
auto optimiseModule(Module *M, OptimizationLevel OptLevel) -> PreservedAnalyses
{
    if (!M) throw invalid_argument("Null ptr argument!");
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

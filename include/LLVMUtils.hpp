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

#ifndef LLVMUtils
#define LLVMUtils

#include <llvm/ADT/iterator_range.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/Passes/PassBuilder.h>

#include <set>
#include <string>
#include <vector>

namespace llvm_utils {

// Create abbreviation for very long function
template <typename RangeT>
auto early_inc(RangeT &&Range) {    // NOLINT
    return llvm::make_early_inc_range(Range);
}

// Print LLVM value to string object
auto str(const llvm::Value *) -> std::string;
auto str(const llvm::Type *) -> std::string;

// Convert boolean to readable string
auto boolToStr(bool) -> std::string;

// True if the argument is known NOT to be defined by the user (i.e. known not in file in /home/*)
auto isSysDef(const llvm::Instruction *const) -> bool;

// Check if address marked dead is certain to never become alive again after lifetime end marker
auto staysDead(llvm::IntrinsicInst *) -> bool;

// Get source row and column location if known (needs debug symbols); {-1, -1} if unknown location
auto getSrcLoc(const llvm::Instruction *) -> std::pair<int64_t, int64_t>;

// Get string with the name of the function & the file where the function is defined
auto getSrcLocStr(const llvm::Function *) -> std::string;

// Functions for determining whether given type or value is, contains, or uses a var-arg object
auto isVarArgList(const llvm::Type *) -> bool;
auto isOrHasVarArgList(const llvm::Type *) -> bool;
auto isVarArgVal(const llvm::Value *) -> bool;

// Create/get function type for return type and optional list of argument types
auto getFnTy(llvm::Type *) -> llvm::FunctionType *;
auto getFnTy(llvm::Type *, std::vector<llvm::Type *>) -> llvm::FunctionType *;

// Determine if function/call/instruction is definitely memory safe (unsafe if uncertain)
auto possibleUnsafe(const llvm::CallBase *) -> bool;
auto possibleUnsafe(llvm::Function *, llvm::FunctionAnalysisManager * = nullptr) -> bool;

// Get underlying called function even if function is some sort of statepoint instruction
auto getCalledFn(const llvm::CallBase *) -> llvm::Function *;

// Checker functions for determining if the given instruction is a lifetime end/start marker
auto isLifetimeStart(const llvm::Instruction *) -> bool;
auto isLifetimeEnd(const llvm::Instruction *) -> bool;

// Get set of all alloca instructions that could have allocated the lifetime marker's address
auto getAllocas(const llvm::IntrinsicInst *) -> std::set<llvm::AllocaInst *>;

// Dump LLVM module IR to file
auto dumpIR(const llvm::Module *, std::string) -> void;

// Function for retrieving a module's global constructors
auto getGlobalCtorsVar(const llvm::Module &) -> llvm::GlobalVariable *;
auto getGlobalCtors(llvm::GlobalVariable *) -> std::vector<std::pair<uint32_t, llvm::Function *>>;

// Run the the default O0, O1, O2, or O3 optimisation pass pipelines on the given module
auto optimiseModule(llvm::Module *, llvm::PassBuilder::OptimizationLevel)
        -> llvm::PreservedAnalyses;

};    // namespace llvm_utils

#endif    // LLVMUtils

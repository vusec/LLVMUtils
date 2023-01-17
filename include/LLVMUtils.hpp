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

// Print LLVM value to string object
template <typename T>
auto str(T *V) -> std::string;
template <typename T>
auto str(T &V) -> std::string;

// Convert boolean to readable string
auto boolToStr(bool) -> std::string;

// True if the argument is known NOT to be defined by the user (i.e. known not in file in /home/*)
auto isSysDef(llvm::Value *) -> bool;
auto isSysDef(llvm::Function *) -> bool;
auto isSysDef(llvm::Instruction *) -> bool;

// Check if address marked dead is certain to never become alive again after lifetime end marker
auto staysDead(llvm::IntrinsicInst *) -> bool;

// Get source row and column location if known (needs debug symbols); {-1, -1} if unknown location
auto getSrcLoc(llvm::Instruction *) -> std::pair<int64_t, int64_t>;

// Get string with the name of the function & the file where the function is defined
auto getSrcLocStr(llvm::Function *) -> std::string;

// Functions for determining whether given type or value is, contains, or uses a var-arg object
auto isVarArgList(llvm::Type *) -> bool;
auto isOrHasVarArgList(llvm::Type *) -> bool;
auto isOrHasVarArgList(llvm::Value *) -> bool;

// Create/get function type for return type and optional list of argument types
auto getFnTy(llvm::Type *) -> llvm::FunctionType *;
auto getFnTy(llvm::Type *, std::vector<llvm::Type *>) -> llvm::FunctionType *;

// Determine if function/call/instruction is definitely memory safe (unsafe if uncertain)
auto guaranteedSafeCall(llvm::CallBase *) -> bool;
auto guaranteedSafeFn(llvm::Function *) -> bool;
auto guaranteedSafeFn(llvm::FunctionAnalysisManager &, llvm::Function *) -> bool;

// Get underlying called function even if function is some sort of statepoint instruction
auto getCalledFn(llvm::CallBase *) -> llvm::Function *;

// Checker functions for determining if the given instruction is a lifetime end/start marker
auto isLifetimeStart(llvm::Instruction *) -> bool;
auto isLifetimeEnd(llvm::Instruction *) -> bool;

// Get set of all alloca instructions that could have allocated the lifetime marker's address
auto getAllocas(llvm::IntrinsicInst *) -> std::set<llvm::AllocaInst *>;

// Add metadata to LLVM value iff the value's type takes metadata (global objects & instructions)
auto addMetadata(llvm::Value *, const llvm::StringRef &, llvm::MDNode *) -> bool;

// Take two types and add them in a new struct type holding both types
auto wrapTypes(llvm::Type *, llvm::Type *) -> llvm::Type *;

// Run the the default O0, O1, O2, or O3 optimisation pass pipelines on the given module
auto optimiseModule(llvm::Module *, llvm::PassBuilder::OptimizationLevel)
        -> llvm::PreservedAnalyses;

};    // namespace llvm_utils

#endif    // LLVMUtils

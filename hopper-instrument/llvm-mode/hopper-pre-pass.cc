/*
  Make optimization fail for branches
  e.g
  if (x == 1 & y == 1) {}
  =>
  if (x==1) {
    if (y == 1) {}
  }
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "debug.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/ADT/SmallSet.h"

#if LLVM_VERSION_MAJOR >= 11
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#else
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

using namespace llvm;

namespace {

bool pre_process(Module &M) {
  SAYF("start hopper pre-process..\n");
  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  Type *VoidTy = Type::getVoidTy(C);

  srandom(1851655);

  Type *FnArgs[1] = {Int32Ty};
  FunctionType *FnTy = FunctionType::get(VoidTy, FnArgs, /*isVarArg=*/false);
  FunctionCallee BranchStub = M.getOrInsertFunction("__hopper_branch_stub", VoidTy, Int32Ty);

  for (auto &F : M) {
    // if the function is declaration, ignore
    if (F.isDeclaration()) return false;

#ifdef DISABLE_PRE_PROCESS
    return false;
#endif

    SmallSet<BasicBlock *, 20> VisitedBB;
    LLVMContext &C = F.getContext();
    for (auto &BB : F) {
      Instruction *Inst = BB.getTerminator();
      if (isa<BranchInst>(Inst)) {
        BranchInst *BI = dyn_cast<BranchInst>(Inst);

        if (BI->isUnconditional() || BI->getNumSuccessors() < 2) continue;

        Value *Cond = BI->getCondition();
        if (!Cond) continue;

        for (unsigned int i = 0; i < BI->getNumSuccessors(); i++) {
          BasicBlock *B0 = BI->getSuccessor(i);
          if (B0 && VisitedBB.count(B0) == 0) {
            VisitedBB.insert(B0);
            BasicBlock::iterator IP = B0->getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));
            unsigned int cur_loc = random() % 1048576;
            CallInst *Call = IRB.CreateCall(
                BranchStub, {ConstantInt::get(Int32Ty, cur_loc)});
            Call->setMetadata(C.getMDKindID("stub"), MDNode::get(C, None));
          }
        }
      }
    }
  }
  return true;
}

#if LLVM_VERSION_MAJOR >= 11
struct HopperPreProcess : public PassInfoMixin<HopperPreProcess> {
 public:
  HopperPreProcess() {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    pre_process(M);
    return PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};

#endif
struct LegacyHopperPreProcess : public ModulePass {
 public:
  static char ID;
  LegacyHopperPreProcess() : ModulePass(ID) {}
  bool runOnModule(Module &M) override {
    pre_process(M);
    return true;
  }
};
}  // namespace

char LegacyHopperPreProcess::ID = 0;

#if LLVM_VERSION_MAJOR < 11

static void registerPrePass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new LegacyHopperPreProcess());
}

static RegisterStandardPasses RegisterPass(
    PassManagerBuilder::EP_EarlyAsPossible, registerPrePass);

/*
static RegisterStandardPasses RegisterPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerPrePass);
*/

#else

llvm::PassPluginLibraryInfo getHopperPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "HopperPreProcess", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(HopperPreProcess());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "HopperPreProcess") {
                    MPM.addPass(HopperPreProcess());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getHopperPluginInfo();
}

#endif
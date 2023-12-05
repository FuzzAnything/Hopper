/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define HOPEPR_COV_PASS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "debug.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
// #include "llvm/IR/DebugInfo.h"
// #include "llvm/Support/Debug.h"

#if LLVM_VERSION_MAJOR >= 11
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#else
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

// #include "llvm/Pass.h"
// #include "llvm/Analysis/TargetLibraryInfo.h"
// #include "llvm/Analysis/MemoryBuiltins.h"
// #include "llvm/Analysis/LoopInfo.h"

// #define ENABLE_TRACE_STRCMP

using namespace llvm;

namespace {

struct ModuleCovInstrument {
  Module &M;

  // Types
  IntegerType *Int8Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  Type *Int8PtrTy;
  Type *Int64PtrTy;
  Type *VoidTy;
  GlobalVariable *HopperMapPtr;
  GlobalVariable *HopperPrevLoc;
  GlobalVariable *HopperContext;
  FunctionCallee TraceCmp;
  FunctionCallee TraceSw;
  FunctionCallee TraceCmpFn;

  // States
  unsigned int inst_ratio = 100;
  unsigned NoSanMetaId;
  MDTuple *NoneMetaNode;
  int inst_blocks = 0;
  uint64_t RandSeed = 1;
  DenseSet<u32> UniqCidSet;

  // std::function<const TargetLibraryInfo &(Function &)> GetTLI;

 public:
  ModuleCovInstrument(Module &M) : M(M) {
    /* Basic types */
    LLVMContext &C = M.getContext();
    VoidTy = Type::getVoidTy(C);
    Int8Ty = IntegerType::getInt8Ty(C);
    Int32Ty = IntegerType::getInt32Ty(C);
    Int64Ty = IntegerType::getInt64Ty(C);
    Int8PtrTy = PointerType::get(Int8Ty, 0);
    Int64PtrTy = PointerType::getUnqual(Int64Ty);
    NoSanMetaId = C.getMDKindID("nosanitize");
    NoneMetaNode = MDNode::get(C, None);

    SAYF("start hopper coverage instrumentation..\n");

    /* Decide instrumentation ratio */
    char *inst_ratio_str = getenv("HOPPER_INST_RATIO");

    if (inst_ratio_str) {
      if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
          inst_ratio > 100)
        FATAL("Bad value of HOPPER_INST_RATIO (must be between 1 and 100)");
    }

    /* Get globals for the SHM region and the previous location. */
    HopperMapPtr =
        new GlobalVariable(M, Int8PtrTy, false, GlobalValue::CommonLinkage,
                           ConstantInt::get(Int32Ty, 0), "__hopper_area_ptr");

    HopperPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::CommonLinkage,
        ConstantInt::get(Int32Ty, 0xFFFFFFFF), "__hopper_prev_loc", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);

    HopperContext =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                           ConstantInt::get(Int32Ty, 0), "__hopper_context", 0,
                           GlobalVariable::GeneralDynamicTLSModel, 0, false);

    TraceCmp = M.getOrInsertFunction("__hopper_trace_cmp", VoidTy, Int32Ty,
                                     Int64Ty, Int64Ty, Int32Ty);
    TraceSw = M.getOrInsertFunction("__hopper_trace_switch", VoidTy, Int32Ty,
                                    Int64Ty, Int32Ty, Int64PtrTy, Int32Ty);
    TraceCmpFn = M.getOrInsertFunction("__hopper_trace_cmp_fn", VoidTy, Int32Ty,
                                       Int8PtrTy, Int8PtrTy, Int32Ty);
  }

  bool skipBasicBlock() { return (random() % 100) >= inst_ratio; }

  u32 getRandomBasicBlockId() { return random() % MAP_SIZE; };

  void setInsNonSan(Instruction *ins) {
    if (ins) ins->setMetadata(NoSanMetaId, NoneMetaNode);
  }

  void setValueNonSan(Value *v) {
    if (Instruction *ins = dyn_cast<Instruction>(v)) setInsNonSan(ins);
  }

  u32 getRandomNum() {
    RandSeed = RandSeed * 1103515245 + 12345;
    return (u32)RandSeed;
  }

  u32 getInstructionId(Instruction *Inst) {
    u32 h = getRandomNum();
    while (UniqCidSet.count(h) > 0) {
      h = h * 3 + 1;
    }
    UniqCidSet.insert(h);
    return h;
  }

  void countEdge(BasicBlock &BB) {
    if (skipBasicBlock()) return;

    BasicBlock::iterator IP = BB.getFirstInsertionPt();
    Instruction *InsertPoint = &*(IP);

    /*
    errs() << "[INS] " << *InsertPoint << "\n";
    if (DILocation *Loc = InsertPoint->getDebugLoc()) {
      errs() << "[LOC] " << cast<DIScope>(Loc->getScope())->getFilename()
             << ", Ln " << Loc->getLine() << ", Col " << Loc->getColumn()
             << "\n";
    }
    */

    IRBuilder<> IRB(InsertPoint);

    /* Make up cur_loc */
    unsigned int cur_loc = getRandomBasicBlockId();
    ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

    /* Load prev_loc */
    LoadInst *PrevLoc = IRB.CreateLoad(Int32Ty, HopperPrevLoc);
    setInsNonSan(PrevLoc);
    Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, Int32Ty);
    setValueNonSan(PrevLocCasted);

    // Check PrevLoc
    Value *CmpNe =
        IRB.CreateICmpNE(PrevLocCasted, ConstantInt::get(Int32Ty, 0xFFFFFFFF));
    setValueNonSan(CmpNe);
    BranchInst *BI =
        cast<BranchInst>(SplitBlockAndInsertIfThen(CmpNe, InsertPoint, false));
    setInsNonSan(BI);
    IRB.SetInsertPoint(BI);

    /* Load SHM pointer */
    LoadInst *MapPtr = IRB.CreateLoad(Int8PtrTy, HopperMapPtr);
    setInsNonSan(MapPtr);
    Value *BrId = IRB.CreateXor(PrevLocCasted, CurLoc);
    setValueNonSan(BrId);
    Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, BrId);
    setValueNonSan(MapPtrIdx);

    /* Update bitmap */
    // Increase 1 : IncRet <- Map[idx] + 1
    LoadInst *Counter = IRB.CreateLoad(Int8Ty, MapPtrIdx);
    setInsNonSan(Counter);

    // Implementation of saturating counter.
    // Value *CmpOF = IRB.CreateICmpNE(Counter, ConstantInt::get(Int8Ty, -1));
    // setValueNonSan(CmpOF);
    // Value *IncVal = IRB.CreateZExt(CmpOF, Int8Ty);
    // setValueNonSan(IncVal);
    // Value *IncRet = IRB.CreateAdd(Counter, IncVal);
    // setValueNonSan(IncRet);

    // Implementation of Never-zero counter
    // The idea is from Marc and Heiko in AFLPlusPlus
    // Reference: :
    // https://github.com/vanhauser-thc/AFLplusplus/blob/master/llvm_mode/README.neverzero
    // and https://github.com/vanhauser-thc/AFLplusplus/issues/10

    Value *IncRet = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
    setValueNonSan(IncRet);
    Value *IsZero = IRB.CreateICmpEQ(IncRet, ConstantInt::get(Int8Ty, 0));
    setValueNonSan(IsZero);
    Value *IncVal = IRB.CreateZExt(IsZero, Int8Ty);
    setValueNonSan(IncVal);
    IncRet = IRB.CreateAdd(IncRet, IncVal);
    setValueNonSan(IncRet);
    // Store Back Map[idx]
    StoreInst *StoreValue = IRB.CreateStore(IncRet, MapPtrIdx);
    setInsNonSan(StoreValue);

    /* Set prev_loc to cur_loc >> 1 */
    // API sensitive context
    // Load ctx
    LoadInst *CtxVal = IRB.CreateLoad(Int32Ty, HopperContext);
    setInsNonSan(CtxVal);
    Value *CtxValCasted = IRB.CreateZExt(CtxVal, Int32Ty);
    setValueNonSan(CtxValCasted);

    // Udate PrevLoc
    Value *NewPrevLoc =
        IRB.CreateXor(CtxValCasted, ConstantInt::get(Int32Ty, cur_loc >> 1));
    StoreInst *StorePrev = IRB.CreateStore(NewPrevLoc, HopperPrevLoc);
    setInsNonSan(StorePrev);

    inst_blocks++;
  }

  Value *castArgType(IRBuilder<> &IRB, Value *V) {
    Type *OpType = V->getType();
    Value *NV = V;
    if (OpType->isFloatTy()) {
      NV = IRB.CreateFPToUI(V, Int32Ty);
      setValueNonSan(NV);
      NV = IRB.CreateIntCast(NV, Int64Ty, false);
      setValueNonSan(NV);
    } else if (OpType->isDoubleTy()) {
      NV = IRB.CreateFPToUI(V, Int64Ty);
      setValueNonSan(NV);
    } else if (OpType->isPointerTy()) {
      NV = IRB.CreatePtrToInt(V, Int64Ty);
    } else {
      if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
        NV = IRB.CreateZExt(V, Int64Ty);
      }
    }
    return NV;
  }

  void processCmp(Instruction *Cond, Constant *Cid, Instruction *InsertPoint) {
    CmpInst *Cmp = dyn_cast<CmpInst>(Cond);
    Value *OpArg[2];
    OpArg[0] = Cmp->getOperand(0);
    OpArg[1] = Cmp->getOperand(1);
    Type *OpType = OpArg[0]->getType();
    if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
          OpType->isFloatTy() || OpType->isDoubleTy())) {
      //|| OpType->isPointerTy()
      return;
    }
    int num_bytes = OpType->getScalarSizeInBits() / 8;
    if (num_bytes == 0) {
      if (OpType->isPointerTy()) {
        num_bytes = 8;
      } else {
        return;
      }
    }

    // skip compare zero and one
    for (int i = 0; i < 2; i++) {
      if (ConstantInt *CI = dyn_cast<ConstantInt>(OpArg[i])) {
        if (CI->isZero() || CI->isOne() || CI->isMinusOne()) {
          return;
        }
      }
    }

    IRBuilder<> IRB(InsertPoint);

    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    Value *Size = ConstantInt::get(Int32Ty, num_bytes);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmp, {Cid, OpArg[0], OpArg[1], Size});
    setInsNonSan(ProxyCall);
  }

  void visitCmpInst(Instruction *Inst) {
    Instruction *InsertPoint = Inst->getNextNode();
    if (!InsertPoint || isa<ConstantInt>(Inst)) return;
    Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
    processCmp(Inst, Cid, InsertPoint);
  }

  void visitSwitchInst(Module &M, Instruction *Inst) {
    SwitchInst *Sw = dyn_cast<SwitchInst>(Inst);
    Value *Cond = Sw->getCondition();

    if (!(Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond))) {
      return;
    }

    int num_bits = Cond->getType()->getScalarSizeInBits();
    int num_bytes = num_bits / 8;
    if (num_bytes == 0 || num_bits % 8 > 0) return;

    Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
    IRBuilder<> IRB(Sw);
    Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);
    setValueNonSan(CondExt);
    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    SmallVector<Constant *, 16> ArgList;
    for (auto It : Sw->cases()) {
      Constant *C = It.getCaseValue();
      if (C->getType()->getScalarSizeInBits() > Int64Ty->getScalarSizeInBits())
        continue;
      ArgList.push_back(ConstantExpr::getCast(CastInst::ZExt, C, Int64Ty));
    }
    ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, ArgList.size());
    GlobalVariable *ArgGV = new GlobalVariable(
        M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
        ConstantArray::get(ArrayOfInt64Ty, ArgList),
        "__hopper_switch_arg_values");
    Value *SwNum = ConstantInt::get(Int32Ty, ArgList.size());
    Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);
    setValueNonSan(ArrPtr);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceSw, {Cid, CondExt, SizeArg, ArrPtr, SwNum});
    setInsNonSan(ProxyCall);
  }

  void visitCallInst(Instruction *Inst) {
    if (!isa<CallInst>(Inst)) {
      return;
    }
    CallInst *Caller = dyn_cast<CallInst>(Inst);
    Function *Callee = Caller->getCalledFunction();

    if (!Callee || Callee->isIntrinsic() ||
        isa<InlineAsm>(Caller->getCalledOperand())) {
      return;
    }

    // remove inserted "stub" functions
    StringRef CallName = Callee->getName();
    if (!CallName.compare(StringRef("__hopper_branch_stub"))) {
      if (Caller->use_empty()) {
        Caller->eraseFromParent();
      }
      return;
    }

    // TODO: indirect call?

    // find out resource related function
    // TODO: newest LLVM has getAllocFnKind;
    /*
    auto TLI = GetTLI(*Callee);
    if (isAllocationFn(Inst, &TLI)) {
      // auto size = getAllocationFamily(Caller, &TLI).value_or(0);
      SAYF("call %s is alloc, size: %d\n", CallName, 0);
      if (isMallocOrCallocLikeFn(Inst, &TLI)) {

      } else if (isReallocLikeFn(Inst, &TLI)) {

      }
      return;
    } else if (isFreeCall(Inst, &TLI) != NULL) {
      SAYF("call %s is free\n", CallName);
      return;
    }
    */

    // find out compare related function
    // we trace strcmp via plthook now.
#ifdef ENABLE_TRACE_STRCMP
    Value *ArgSize = nullptr;
    if (!CallName.compare(StringRef("strcmp")) ||
        !CallName.compare(StringRef("strcoll")) ||
        !CallName.compare(StringRef("_ZNKSt7__cxx1112basic_stringIcSt11char_"
                                    "traitsIcESaIcEE7compareEPKc")) ||
        !CallName.compare(StringRef("_ZSteqIcSt11char_traitsIcESaIcEEbRKNSt7__"
                                    "cxx1112basic_stringIT_T0_T1_EEPKS5_"))) {
      ArgSize = ConstantInt::get(Int32Ty, 0);
    } else if (!CallName.compare(StringRef("strncmp")) ||
               !CallName.compare(StringRef("memcmp"))) {
      ArgSize = Caller->getArgOperand(2);  // int32ty
    } else {
      return;
    }

    // int arg_num = Caller->getNumOperands();
    // SAYF("%s arg num %d\n", CallName, arg_num);

    Value *OpArg[2];
    OpArg[0] = Caller->getArgOperand(0);
    OpArg[1] = Caller->getArgOperand(1);

    if (!OpArg[0]->getType()->isPointerTy() ||
        !OpArg[1]->getType()->isPointerTy()) {
      return;
    }

    ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));

    IRBuilder<> IRB(Inst);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpFn, {Cid, OpArg[0], OpArg[1], ArgSize});
    setInsNonSan(ProxyCall);
#endif
  }

  void instrument() {
    LLVMContext &C = M.getContext();

    for (auto &F : M) {
      if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
        continue;

      std::vector<BasicBlock *> bb_list;
      for (auto bb = F.begin(); bb != F.end(); bb++) bb_list.push_back(&(*bb));

      for (auto bi = bb_list.begin(); bi != bb_list.end(); bi++) {
        BasicBlock *BB = *bi;
        std::vector<Instruction *> inst_list;

        for (auto inst = BB->begin(); inst != BB->end(); inst++) {
          Instruction *Inst = &(*inst);
          inst_list.push_back(Inst);
        }
        if (inst_list.empty()) {
          continue;
        }
        countEdge(*BB);
        for (auto inst = inst_list.begin(); inst != inst_list.end(); inst++) {
          Instruction *Inst = *inst;
          if (Inst->getMetadata(NoSanMetaId)) continue;
          if (isa<CallInst>(Inst)) {
            visitCallInst(Inst);
          } else if (isa<InvokeInst>(Inst)) {
            // visitInvokeInst(Inst);
          } else if (isa<SwitchInst>(Inst)) {
            visitSwitchInst(M, Inst);
          } else if (isa<CmpInst>(Inst)) {
            visitCmpInst(Inst);
          } else {
            // visitExploitation(Inst);
          }
        }
      }
    }
  }

  // OKF("#bb: %d", inst_blocks);
};

#if LLVM_VERSION_MAJOR >= 11
struct HopperCoverage : public PassInfoMixin<HopperCoverage> {
 public:
  HopperCoverage() {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    // FunctionAnalysisManager &FAM =
    //     MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    // auto GetTLI = [&](Function &F) -> const TargetLibraryInfo & {
    //   return FAM.getResult<TargetLibraryAnalysis>(F);
    // };

    ModuleCovInstrument cov = ModuleCovInstrument(M);
    cov.instrument();
    return PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};
#else
struct LegacyHopperCoverage : public ModulePass {
 public:
  static char ID;
  LegacyHopperCoverage() : ModulePass(ID) {}
  bool runOnModule(Module &M) override {
    // auto GetTLI = [&](Function &F) -> TargetLibraryInfo & {
    //   return this->getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
    // };
    ModuleCovInstrument cov = ModuleCovInstrument(M);
    cov.instrument();
    return true;
  }
  /*
    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.addRequired<TargetTransformInfoWrapperPass>();
    }
  */
};

char LegacyHopperCoverage::ID = 0;
#endif

}  // namespace

#if LLVM_VERSION_MAJOR < 11

static void registerCovPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
  PM.add(new LegacyHopperCoverage());
}

static RegisterStandardPasses RegisterPass(PassManagerBuilder::EP_OptimizerLast,
                                           registerCovPass);

static RegisterStandardPasses RegisterPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCovPass);

#else

llvm::PassPluginLibraryInfo getHopperPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "HopperCoverage", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(HopperCoverage());
                });
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "HopperCoverage") {
                    MPM.addPass(HopperCoverage());
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

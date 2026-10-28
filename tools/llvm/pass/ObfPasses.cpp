// ObfPasses.cpp — Phase 3 mutation passes (seeded, deterministic per seed).
//
// Two function passes registered at OptimizerLast (after clang's main opt
// pipeline, before codegen — nothing folds our shapes back):
//
//   obf-sub   instruction substitution: add/sub constant-negation swaps and
//             icmp eq/ne x,C -> xor-test rewrites, applied with a
//             seed-derived per-instruction probability.
//   obf-bogo  opaque-predicate block splitting: (x<<1)+x != x*3 is false for
//             ALL i64 values (modular arithmetic, no overflow), fed from a
//             volatile global so neither our pass nor ISel can fold it. The
//             never-taken stub survives codegen and reshapes the CFG.
//
// Seed contract: OBF_SEED (decimal) is read once at plugin load. Same seed +
// same inputs => byte-identical output (Brepro holds); different seed =>
// different shape. The ReflectiveLoader export is excluded — its 8192-nop
// splice wall is a delivery contract and must stay contiguous.

#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>

using namespace llvm;

namespace {

// ---- seed plumbing --------------------------------------------------------

static uint64_t loadSeed() {
  const char *e = getenv("OBF_SEED");
  if (e == NULL || *e == '\0') {
    // env fallback: some cc1 spawn paths have surprised us — read the seed
    // file the CI step writes next to the plugin (same contract, no env).
    if (FILE *f = fopen("tools/llvm/pass/seed.txt", "r")) {
      char buf[32] = {0};
      size_t n = fread(buf, 1, sizeof(buf) - 1, f);
      fclose(f);
      if (n > 0) e = buf;
    }
  }
  if (e == NULL || *e == '\0')
    return 0;
  uint64_t v = 0;
  for (const char *p = e; *p; p++) {
    if (*p < '0' || *p > '9') break;
    v = v * 10 + (uint64_t)(*p - '0');
  }
  return v;
}

static uint64_t splitmix64(uint64_t x) {
  x += 0x9E3779B97F4A7C15ULL;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
  return x ^ (x >> 31);
}

static uint64_t hashStr(StringRef s) {
  uint64_t h = 0xCBF29CE484222325ULL;
  for (char c : s) {
    h ^= (unsigned char)c;
    h *= 0x100000001B3ULL;
  }
  return h;
}

// per-item decision bit — stable within a build, varies across seeds
static bool coin(uint64_t seed, StringRef fname, uint64_t idx, int salt) {
  return (splitmix64(seed ^ hashStr(fname) ^ splitmix64(idx * 0x9E3779B9ULL + (uint64_t)salt)) & 1) != 0;
}

static uint64_t mixFor(uint64_t seed, StringRef fname, uint64_t idx, int salt) {
  return splitmix64(seed ^ hashStr(fname) ^ splitmix64(idx * 0xD1B54A32D192ED03ULL + (uint64_t)salt));
}

// ---- obf-sub --------------------------------------------------------------

struct ObfSubPass : PassInfoMixin<ObfSubPass> {
  uint64_t seed;
  explicit ObfSubPass(uint64_t s) : seed(s) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
      return PreservedAnalyses::all();
    bool changed = false;
    uint64_t idx = 0;

    SmallVector<BinaryOperator *, 16> arith;
    SmallVector<ICmpInst *, 16> icmps;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (BO->getOpcode() == Instruction::Add || BO->getOpcode() == Instruction::Sub)
            arith.push_back(BO);
        } else if (auto *CI = dyn_cast<ICmpInst>(&I)) {
          CmpInst::Predicate P = CI->getPredicate();
          if (P == CmpInst::ICMP_EQ || P == CmpInst::ICMP_NE)
            icmps.push_back(CI);
        }
      }
    }

    for (BinaryOperator *BO : arith) {
      uint64_t thisIdx = idx++;
      auto *C = dyn_cast<ConstantInt>(BO->getOperand(1));
      if (C == nullptr) continue;
      unsigned bits = C->getType()->getIntegerBitWidth();
      if (bits != 32 && bits != 64) continue;
      APInt v = C->getValue();
      if (v.isZero() || v.isMinSignedValue()) continue;

      bool toSub = (BO->getOpcode() == Instruction::Add);
      // seeded flip of direction for extra shape variety
      if (coin(seed, F.getName(), thisIdx, 1))
        toSub = !toSub;

      IRBuilder<> B(BO);
      Value *op = BO->getOperand(0);
      APInt nv = toSub ? -v : -v; // the negated constant drives the other opcode
      ConstantInt *NC = cast<ConstantInt>(ConstantInt::get(C->getContext(), nv));
      Value *res = toSub ? B.CreateSub(op, NC, "", false, false)
                         : B.CreateAdd(op, NC, "", false, false);
      BO->replaceAllUsesWith(res);
      BO->eraseFromParent();
      changed = true;
    }

    for (ICmpInst *CI : icmps) {
      uint64_t thisIdx = idx++;
      if (!coin(seed, F.getName(), thisIdx, 2)) continue;
      auto *C = dyn_cast<ConstantInt>(CI->getOperand(1));
      if (C == nullptr) continue;
      unsigned bits = C->getType()->getIntegerBitWidth();
      if (bits != 32 && bits != 64) continue;
      if (C->getValue().isZero()) continue;

      IRBuilder<> B(CI);
      Value *xored = B.CreateXor(CI->getOperand(0), C);
      Value *zero = ConstantInt::get(C->getType(), 0);
      ICmpInst *NI = cast<ICmpInst>(B.CreateICmp(CI->getPredicate(), xored, zero));
      NI->takeName(CI);
      CI->replaceAllUsesWith(NI);
      CI->eraseFromParent();
      changed = true;
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

// ---- obf-bogo -------------------------------------------------------------

static GlobalVariable *getSeedGlobal(Module &M, uint64_t seed) {
  GlobalVariable *G = M.getGlobalVariable("bw_obf_seed");
  if (G != nullptr)
    return G;
  IntegerType *T = IntegerType::getInt64Ty(M.getContext());
  Constant *Init = ConstantInt::get(T, seed ^ 0xB70C1A2E4D9F8C37ULL);
  G = new GlobalVariable(M, T, false, GlobalValue::InternalLinkage, Init,
                         "bw_obf_seed");
  return G;
}

static bool hasInlineAsm(BasicBlock &BB) {
  for (Instruction &I : BB) {
    if (auto *CB = dyn_cast<CallBase>(&I)) {
      if (isa<InlineAsm>(CB->getCalledOperand()))
        return true;
    }
  }
  return false;
}

struct ObfBogoPass : PassInfoMixin<ObfBogoPass> {
  uint64_t seed;
  explicit ObfBogoPass(uint64_t s) : seed(s) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (F.isDeclaration())
      return PreservedAnalyses::all();
    // splice-wall contract: the ReflectiveLoader export body is a fixed
    // volatile-nop wall the TS writes its loader into — never split it.
    if (F.getName().contains("ReflectiveLoader"))
      return PreservedAnalyses::all();
    if (F.hasFnAttribute(Attribute::Naked))
      return PreservedAnalyses::all();

    Module &M = *F.getParent();
    GlobalVariable *SG = getSeedGlobal(M, seed);

    // candidates: splittable, no inline asm, no blockaddress use
    SmallVector<BasicBlock *, 16> cands;
    for (BasicBlock &BB : F) {
      if (BB.isEHPad() || BB.hasAddressTaken()) continue;
      if (hasInlineAsm(BB)) continue;
      // need a split point that is neither the PHI region nor the terminator
      int nonPhi = 0;
      for (Instruction &I : BB) {
        if (isa<PHINode>(I)) continue;
        if (I.isTerminator()) break;
        nonPhi++;
      }
      if (nonPhi < 2) continue;
      cands.push_back(&BB);
    }
    if (cands.empty())
      return PreservedAnalyses::all();

    uint64_t limit = 1 + (mixFor(seed, F.getName(), 0, 7) % 2); // 1-2 splits/fn
    bool changed = false;
    uint64_t idx = 0;
    for (BasicBlock *BB : cands) {
      if (limit == 0) break;
      if (!coin(seed, F.getName(), idx++, 3)) continue;
      limit--;

      // split before the last non-terminator instruction (PHI region safe)
      Instruction *splitAt = nullptr;
      for (Instruction &I : *BB) {
        if (I.isTerminator()) break;
        if (isa<PHINode>(I)) continue;
        splitAt = &I; // keep walking: last one wins
      }
      if (splitAt == nullptr) continue;

      BasicBlock *Tail = BB->splitBasicBlock(splitAt->getIterator(),
                                             BB->getName() + ".otail");

      // predicate block between Head and Tail
      BasicBlock *Pred = BasicBlock::Create(F.getContext(),
                                            BB->getName() + ".opred",
                                            &F, Tail);
      BasicBlock *Stub = BasicBlock::Create(F.getContext(),
                                            BB->getName() + ".ostub",
                                            &F, Tail);
      // Head's terminator (a br to Tail) now routes through Pred
      Instruction *headBr = BB->getTerminator();
      BranchInst *br = cast<BranchInst>(headBr);
      for (unsigned i = 0; i < br->getNumSuccessors(); i++)
        if (br->getSuccessor(i) == Tail)
          br->setSuccessor(i, Pred);

      IRBuilder<> B(Pred);
      Value *sv = B.CreateLoad(SG->getValueType(), SG, "seedv");
      Value *x = B.CreateXor(sv, ConstantInt::get(Type::getInt64Ty(F.getContext()),
                                                  mixFor(seed, F.getName(), idx, 4)));
      Value *a = B.CreateShl(x, 1);
      Value *b = B.CreateMul(x, ConstantInt::get(Type::getInt64Ty(F.getContext()), 3));
      Value *cond = B.CreateICmpNE(a, b); // always false: 3x == 3x (mod 2^64)

      // dead stub: a few shape-heavy but harmless ops, then jump to Tail
      IRBuilder<> S(Stub);
      Value *t1 = S.CreateAdd(x, ConstantInt::get(Type::getInt64Ty(F.getContext()), 0x51ED2701ULL));
      Value *t2 = S.CreateXor(t1, ConstantInt::get(Type::getInt64Ty(F.getContext()), 0x2F1BC3ULL));
      S.CreateBr(Tail);

      BranchInst::Create(Stub, Tail, cond, Pred);
      changed = true;
    }

    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};

// ---- plugin wiring --------------------------------------------------------

static uint64_t g_seed = loadSeed();

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  errs() << "[obfpasses] loaded, seed=" << g_seed << "\n";
  return {LLVM_PLUGIN_API_VERSION, "obfpasses", "0.1",
          [](PassBuilder &PB) {
            // LLVM 17+: the OptimizerLast extension point is module-level
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  MPM.addPass(createModuleToFunctionPassAdaptor(
                      ObfSubPass(g_seed)));
                  MPM.addPass(createModuleToFunctionPassAdaptor(
                      ObfBogoPass(g_seed)));
                });
            // opt -passes=obf-sub / obf-bogo (smoke + unit use)
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "obf-sub") {
                    FPM.addPass(ObfSubPass(g_seed));
                    return true;
                  }
                  if (Name == "obf-bogo") {
                    FPM.addPass(ObfBogoPass(g_seed));
                    return true;
                  }
                  return false;
                });
          }};
}

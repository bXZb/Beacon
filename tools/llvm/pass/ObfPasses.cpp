// ObfPasses.cpp — Phase 3 mutation passes (seeded, deterministic per seed).
//
// Two function passes registered at OptimizerLast (after clang's main opt
// pipeline, before codegen — nothing folds our shapes back):
//
//   obf-sub   instruction substitution, every rewrite value-exact for ALL
//             inputs: add/sub constant-negation opcode flip OR seeded
//             const-split (x+d = (x+s1)+s2, the IR-level sbb site); icmp
//             eq/ne x,C -> xor-test; relational cmp -> operand-swap with
//             predicate flip or guarded boundary shift (x<v -> x<=v-1,
//             guards exclude the wrap-edge constants); and-split (x&C =
//             (x&(C|A))&C, A a seeded subset of ~C); or-split ((x|C1)|C2,
//             C1|C2 == C disjoint partition). Shape coins are seed-derived;
//             the VALUES are never seeded.
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

// one part of a constant split: add x,s or sub x,-s — both add s to x
static Value *emitArithPart(IRBuilder<> &B, Value *X, const APInt &s,
                            uint64_t seed, StringRef fn, uint64_t idx, int salt) {
  if (coin(seed, fn, idx, salt))
    return B.CreateAdd(X, ConstantInt::get(X->getType(), s), "", false, false);
  return B.CreateSub(X, ConstantInt::get(X->getType(), -s), "", false, false);
}

// x P v  ==>  x NP (v-1 or v+1): exact for ALL x when the edge guard holds
// (the guards exclude exactly the constants where v-1/v+1 wraps)
static bool relShift(CmpInst::Predicate P, const APInt &v,
                     CmpInst::Predicate &NP, APInt &NV) {
  switch (P) {
  case CmpInst::ICMP_ULT: if (v.isZero()) return false;          NP = CmpInst::ICMP_ULE; NV = v - 1; return true;
  case CmpInst::ICMP_ULE: if (v.isAllOnes()) return false;       NP = CmpInst::ICMP_ULT; NV = v + 1; return true;
  case CmpInst::ICMP_UGT: if (v.isAllOnes()) return false;       NP = CmpInst::ICMP_UGE; NV = v + 1; return true;
  case CmpInst::ICMP_UGE: if (v.isZero()) return false;          NP = CmpInst::ICMP_UGT; NV = v - 1; return true;
  case CmpInst::ICMP_SLT: if (v.isMinSignedValue()) return false; NP = CmpInst::ICMP_SLE; NV = v - 1; return true;
  case CmpInst::ICMP_SLE: if (v.isMaxSignedValue()) return false; NP = CmpInst::ICMP_SLT; NV = v + 1; return true;
  case CmpInst::ICMP_SGT: if (v.isMaxSignedValue()) return false; NP = CmpInst::ICMP_SGE; NV = v + 1; return true;
  case CmpInst::ICMP_SGE: if (v.isMinSignedValue()) return false; NP = CmpInst::ICMP_SGT; NV = v - 1; return true;
  default: return false;
  }
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
    SmallVector<BinaryOperator *, 16> ands;
    SmallVector<BinaryOperator *, 16> ors;
    SmallVector<ICmpInst *, 16> icmps;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (BO->getOpcode() == Instruction::Add || BO->getOpcode() == Instruction::Sub)
            arith.push_back(BO);
          else if (BO->getOpcode() == Instruction::And)
            ands.push_back(BO);
          else if (BO->getOpcode() == Instruction::Or)
            ors.push_back(BO);
        } else if (auto *CI = dyn_cast<ICmpInst>(&I)) {
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

      // signed delta added to x: add x,C -> +C ; sub x,C -> -C
      // (min-signed already skipped: -min wraps onto itself)
      APInt delta = (BO->getOpcode() == Instruction::Add) ? v : APInt(bits, 0) - v;

      IRBuilder<> B(BO);
      Value *op = BO->getOperand(0);
      Value *res = nullptr;
      if (coin(seed, F.getName(), thisIdx, 13) && !delta.isAllOnes()) {
        // const-split (the IR-level "sbb" site): x+delta = (x OP1 s1) OP2 s2
        // with s1+s2 == delta, each part add-with-si or sub-with-neg-si.
        // Shape changes regardless of the per-part opcode coin, since both
        // immediates differ from the original single constant.
        APInt s1 = APInt(bits, mixFor(seed, F.getName(), thisIdx, 14)) & delta;
        if (s1.isZero() || s1 == delta)
          s1 = delta + 1;
        if (s1.isZero())
          s1 = delta - 1; // delta == all-ones excluded above, so this lands nonzero
        APInt s2 = delta - s1;
        Value *t = emitArithPart(B, op, s1, seed, F.getName(), thisIdx, 15);
        res = emitArithPart(B, t, s2, seed, F.getName(), thisIdx, 16);
      } else {
        // UNCONDITIONAL opcode flip: add x,C <-> sub x,-C is the ONLY
        // value-equivalent opcode swap here. (An earlier "seeded direction
        // flip" rewrote add x,C into add x,-C — a live-matrix crash — the
        // coin only ever chose whether to BREAK the value.)
        bool toSub = (BO->getOpcode() == Instruction::Add);
        res = toSub ? B.CreateSub(op, ConstantInt::get(C->getContext(), -delta), "", false, false)
                    : B.CreateAdd(op, ConstantInt::get(C->getContext(), delta), "", false, false);
      }
      BO->replaceAllUsesWith(res);
      BO->eraseFromParent();
      changed = true;
    }

    // and-split: x & C = (x & (C|A)) & C with A a seeded nonzero subset of
    // ~C — (C|A)&C == C, so the composition is exact for all x
    for (BinaryOperator *BO : ands) {
      uint64_t thisIdx = idx++;
      auto *C = dyn_cast<ConstantInt>(BO->getOperand(1));
      if (C == nullptr) continue;
      unsigned bits = C->getType()->getIntegerBitWidth();
      if (bits < 8) continue;
      APInt v = C->getValue();
      if (v.isZero() || v.isAllOnes()) continue;
      APInt notv = ~v;
      APInt a = APInt(bits, mixFor(seed, F.getName(), thisIdx, 11)) & notv;
      if (a.isZero())
        a = APInt(bits, 1) << notv.countTrailingZeros();
      APInt c1 = v | a; // differs from v (a != 0), superset of v
      IRBuilder<> B(BO);
      Value *t = B.CreateAnd(BO->getOperand(0), ConstantInt::get(C->getContext(), c1));
      Value *res = B.CreateAnd(t, C);
      BO->replaceAllUsesWith(res);
      BO->eraseFromParent();
      changed = true;
    }

    // or-split: x | C = (x | C1) | C2 with C1|C2 == C, C1/C2 a seeded
    // disjoint partition of C's set bits (needs popcount(C) >= 2)
    for (BinaryOperator *BO : ors) {
      uint64_t thisIdx = idx++;
      auto *C = dyn_cast<ConstantInt>(BO->getOperand(1));
      if (C == nullptr) continue;
      unsigned bits = C->getType()->getIntegerBitWidth();
      if (bits < 8) continue;
      APInt v = C->getValue();
      if (v.isZero() || v.popcount() < 2) continue;
      APInt c1 = APInt(bits, mixFor(seed, F.getName(), thisIdx, 12)) & v;
      if (c1.isZero() || c1 == v)
        c1 = APInt(bits, 1) << v.countTrailingZeros(); // lowest set bit; != v by popcount >= 2
      APInt c2 = v ^ c1; // disjoint remainder, nonzero
      IRBuilder<> B(BO);
      Value *t = B.CreateOr(BO->getOperand(0), ConstantInt::get(C->getContext(), c1));
      Value *res = B.CreateOr(t, ConstantInt::get(C->getContext(), c2));
      BO->replaceAllUsesWith(res);
      BO->eraseFromParent();
      changed = true;
    }

    for (ICmpInst *CI : icmps) {
      uint64_t thisIdx = idx++;
      auto *C = dyn_cast<ConstantInt>(CI->getOperand(1));
      if (C == nullptr) continue;
      unsigned bits = C->getType()->getIntegerBitWidth();
      CmpInst::Predicate P = CI->getPredicate();

      if (P == CmpInst::ICMP_EQ || P == CmpInst::ICMP_NE) {
        if (bits != 32 && bits != 64) continue;
        if (C->getValue().isZero()) continue;

        IRBuilder<> B(CI);
        Value *xored = B.CreateXor(CI->getOperand(0), C);
        Value *zero = ConstantInt::get(C->getType(), 0);
        ICmpInst *NI = cast<ICmpInst>(B.CreateICmp(P, xored, zero));
        NI->takeName(CI);
        CI->replaceAllUsesWith(NI);
        CI->eraseFromParent();
        changed = true;
        continue;
      }

      // relational sites: boundary shift x P v -> x NP (v±1), guarded
      // against the wrap-edge constants. The operand-swap alternative was
      // removed: swap+flip is IR-exact but ISel canonicalizes the constant
      // back to operand 1 and re-emits the identical cmp — a machine-code
      // no-op. KNOWN ABSORPTION LIMIT (proven 2026-11-05, the YARA sig_2
      // survivor): for increment-fed loop bounds (latch icmp on n+1) the
      // backend folds the ADD into the compare — (n+1)<C and (n+1)<=C-1
      // both emit cmp n,C-1; jb — so the IR-level shift is REAL but the
      // bytes stay identical. Only a MachineFunction-level pass could shape
      // those. Edge-guarded sites stay as-is (no exact IR rewrite).
      CmpInst::Predicate NP = P;
      APInt NV = C->getValue();
      if (!relShift(P, C->getValue(), NP, NV))
        continue;
      IRBuilder<> B(CI);
      ICmpInst *NI = cast<ICmpInst>(B.CreateICmp(NP, CI->getOperand(0),
                                                 ConstantInt::get(C->getType(), NV)));
      NI->takeName(CI);
      CI->replaceAllUsesWith(NI);
      CI->eraseFromParent();
      changed = true;
    }

    // xor-split: xor x, C -> xor (xor x, C1), C2 with C1 seeded and
    // C1^C2 == C — behavior-identical, doubles the instruction, and it
    // covers and/xor-heavy regions the add/icmp rewrites miss.
    for (BasicBlock &BB : F) {
      for (Instruction &I : make_early_inc_range(BB)) {
        auto *XO = dyn_cast<BinaryOperator>(&I);
        if (XO == nullptr || XO->getOpcode() != Instruction::Xor) continue;
        auto *C = dyn_cast<ConstantInt>(XO->getOperand(1));
        if (C == nullptr) continue;
        unsigned bits = C->getType()->getIntegerBitWidth();
        if (bits != 32 && bits != 64) continue;
        APInt v = C->getValue();
        if (v.isZero() || v.isAllOnes()) continue;
        uint64_t thisIdx = idx++;
        uint64_t mix = mixFor(seed, F.getName(), thisIdx, 5);
        APInt c1 = APInt(bits, mix & v.getZExtValue() | 1);
        if ((c1 & v) == 0) c1 = APInt(bits, 1);
        APInt c2 = v ^ c1;
        if (c2.isZero()) continue;
        IRBuilder<> B(XO);
        Value *t = B.CreateXor(XO->getOperand(0), ConstantInt::get(C->getContext(), c1));
        Value *res = B.CreateXor(t, ConstantInt::get(C->getContext(), c2));
        XO->replaceAllUsesWith(res);
        XO->eraseFromParent();
        changed = true;
      }
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
  bool disabled;
  explicit ObfBogoPass(uint64_t s)
      : seed(s), disabled(getenv("OBF_NO_BOGO") != nullptr) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
    if (disabled || F.isDeclaration())
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

    // UNCONDITIONAL split (coverage contract: every eligible function gets
    // >=1 opaque branch); count is seed-coined.
    uint64_t limit = 1 + (mixFor(seed, F.getName(), 0, 7) % 2); // 1-2 splits/fn
    bool changed = false;
    uint64_t idx = 0;
    for (BasicBlock *BB : cands) {
      if (limit == 0) break;
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

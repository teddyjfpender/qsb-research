import QSB.Proofs
import QSB.Tiers

/-!
# Facts about the concrete tier scripts

`QSB.Tiers` holds the exact build inputs of the production scripts (tiers A-E, the SHA-1 variant of
A, TS4, and the script of the real TS2 spend). `qsbcheck --scripts` checks that `Build.build`
reproduces Python's bytes for them, so everything below is about the scripts Python emits.

Proved per tier (by `native_decide`, i.e. trusting the Lean compiler for the evaluation):
* size <= 10,000 bytes, every push parses, and only modelled opcodes occur;
* the Core op count (`staticOps`) is <= 201 and equals the builder's own counter; with
  `no_opcount_failure` this means *no* execution of the script can fail on the op limit;
* FindAndDelete of any nonce-pool signature leaves the script unchanged (PUSHDATA1), so the round
  sighash does not depend on which pool signature the spender picks;
* FindAndDelete of any dummy signature removes exactly one push (its own);
* 2-stage tiers: every selection has `A <= m` (`plan_in_region`); 3-stage tiers: not in round 2.
-/

namespace QSB.TierProofs
open QSB QSB.Build

def onlyModelled (is : List Instr) : Bool := is.all fun i => match i with | .other _ => false | _ => true

/-- size, parse, op-count checks -/
def limitsOk (b : Built) : Bool :=
  decide (b.script.length ≤ 10000) &&
  match parse b.script with
  | some is => cmsPreceded is && decide (staticOps is ≤ MAX_OPS) && staticOps is == b.ops && onlyModelled is
  | none => false

/-- no pool signature's minimal push occurs at an opcode boundary of the script -/
def poolSafe (p : Params) (b : Built) : Bool :=
  (List.range p.k).all fun i => !matchAtBoundary (pushMin (derSig 1 (i + 1) 0x01)) b.script

/-- FindAndDelete of every dummy removes exactly one pattern-sized chunk -/
def dummiesExact (b : Built) (rnd : Rand) : Bool :=
  rnd.dummies.all fun ds => ds.all fun d =>
    (findAndDelete (pushMin d) b.script).length + (pushMin d).length == b.script.length

theorem limits_sound (b : Built) (h : limitsOk b = true) :
    b.script.length ≤ 10000 ∧ ∃ is, parse b.script = some is ∧ staticOps is ≤ MAX_OPS ∧
      staticOps is = b.ops ∧ ∀ c st, run c is ⟨st, 0⟩ ≠ .error .opCount := by
  unfold limitsOk at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨hsz, h⟩ := h
  refine ⟨hsz, ?_⟩
  split at h
  · rename_i is his
    simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
    obtain ⟨⟨⟨hp, hs⟩, he⟩, -⟩ := h
    exact ⟨is, his, hs, he, fun c st => no_opcount_failure c is hp hs st⟩
  · simp at h

theorem poolSafe_sound (p : Params) (b : Built) (h : poolSafe p b = true) :
    ∀ i < p.k, findAndDelete (pushMin (derSig 1 (i + 1) 0x01)) b.script = b.script := by
  intro i hi
  unfold poolSafe at h
  have := List.all_eq_true.mp h i (List.mem_range.mpr hi)
  simp only [Bool.not_eq_true'] at this
  exact findAndDelete_id' _ _ this

/-- All tiers at once: size, op count, pool signatures invisible to FindAndDelete. -/
theorem all_tiers_ok : Tiers.all.all (fun (_, p, b) => limitsOk b && poolSafe p b) = true := by
  native_decide

/-- Every selection gadget has its region at least as large as what sits above it (`A <= m`), so
`hors_select`'s second (out-of-region) case cannot occur. -/
def planInRegion (b : Built) : Bool := b.plan.all fun (a, m) => decide (a ≤ m) && decide (1 ≤ m)

/-- 2-stage tiers: every selection stays in its region. -/
theorem plan_in_region :
    planInRegion Tiers.tierA && planInRegion Tiers.tierB && planInRegion Tiers.tierASha1 &&
    planInRegion Tiers.ts4 && planInRegion Tiers.realTs2 = true := by native_decide

/-- 3-stage tiers: in round 2 the items above the region outnumber it (round 1's unused dummies
and commitments sit there), so `hors_select`'s out-of-region case is reachable in principle and is
excluded only by the secrecy of round 1's unrevealed HORS preimages. -/
theorem three_stage_round2_reaches_above :
    planInRegion Tiers.tierC || planInRegion Tiers.tierD || planInRegion Tiers.tierE = false := by native_decide

theorem tierA_limits : limitsOk Tiers.tierA = true := by native_decide
theorem tierB_limits : limitsOk Tiers.tierB = true := by native_decide
theorem tierC_limits : limitsOk Tiers.tierC = true := by native_decide
theorem tierD_limits : limitsOk Tiers.tierD = true := by native_decide
theorem tierE_limits : limitsOk Tiers.tierE = true := by native_decide
theorem tierASha1_limits : limitsOk Tiers.tierASha1 = true := by native_decide
theorem ts4_limits : limitsOk Tiers.ts4 = true := by native_decide
theorem realTs2_limits : limitsOk Tiers.realTs2 = true := by native_decide

/-- Tier A (TS4, 89.7 bits): at most 10,000 bytes, and no execution can hit the 201-op limit. -/
theorem tierA_within_limits : Tiers.tierA.script.length ≤ 10000 ∧ ∃ is, parse Tiers.tierA.script = some is ∧
    staticOps is ≤ 201 ∧ ∀ c st, run c is ⟨st, 0⟩ ≠ .error .opCount := by
  obtain ⟨h1, is, h2, h3, -, h4⟩ := limits_sound _ tierA_limits
  exact ⟨h1, is, h2, h3, h4⟩

/-- Tier E (116 bits): at most 10,000 bytes, and no execution can hit the 201-op limit. -/
theorem tierE_within_limits : Tiers.tierE.script.length ≤ 10000 ∧ ∃ is, parse Tiers.tierE.script = some is ∧
    staticOps is ≤ 201 ∧ ∀ c st, run c is ⟨st, 0⟩ ≠ .error .opCount := by
  obtain ⟨h1, is, h2, h3, -, h4⟩ := limits_sound _ tierE_limits
  exact ⟨h1, is, h2, h3, h4⟩

theorem tierA_pool_never_deleted : ∀ i < Tiers.tierAP.k,
    findAndDelete (pushMin (derSig 1 (i + 1) 0x01)) Tiers.tierA.script = Tiers.tierA.script :=
  poolSafe_sound _ _ (by native_decide)

theorem tierE_pool_never_deleted : ∀ i < Tiers.tierEP.k,
    findAndDelete (pushMin (derSig 1 (i + 1) 0x01)) Tiers.tierE.script = Tiers.tierE.script :=
  poolSafe_sound _ _ (by native_decide)

theorem tiers_dummies_exact :
    dummiesExact Tiers.tierA Tiers.tierAR && dummiesExact Tiers.tierB Tiers.tierBR &&
    dummiesExact Tiers.tierC Tiers.tierCR && dummiesExact Tiers.tierD Tiers.tierDR &&
    dummiesExact Tiers.tierE Tiers.tierER && dummiesExact Tiers.tierASha1 Tiers.tierASha1R = true := by
  native_decide

end QSB.TierProofs

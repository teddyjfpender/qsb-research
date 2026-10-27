import QSB
-- Printed by check.sh: the proofs must use no `sorryAx`. `Lean.ofReduceBool` appears exactly for
-- the `native_decide` tier facts (evaluation trusted to the compiler).
#print axioms QSB.numDec_numEnc
#print axioms QSB.hors_gadget
#print axioms QSB.hors_select
#print axioms QSB.findAndDelete_id'
#print axioms QSB.pushMin_not_prefix_pushdata1
#print axioms QSB.run_opcount
#print axioms QSB.no_opcount_failure
#print axioms QSB.TierProofs.all_tiers_ok
#print axioms QSB.TierProofs.tierA_within_limits
#print axioms QSB.TierProofs.tierE_within_limits
#print axioms QSB.TierProofs.tierA_pool_never_deleted
#print axioms QSB.TierProofs.tiers_dummies_exact
#print axioms QSB.TierProofs.plan_in_region
#print axioms QSB.TierProofs.three_stage_round2_reaches_above
#print axioms QSB.Blocks.parse_build_TS2
#print axioms QSB.Gadget.gadget_spec
#print axioms QSB.TS2.loop
#print axioms QSB.TS2.ts2_family_sound
#print axioms QSB.TS2Instances.realTs2_sound
#print axioms QSB.TS2Instances.ts2_sound

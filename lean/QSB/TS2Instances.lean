import QSB.TS2
import QSB.Tiers

/-!
# M3 instances

The design of the real TS2 spend (`real/script.hex`, accepted by Bitcoin Core with GPU-found hits)
satisfies `SideTS2` (checked by `native_decide`), so its production script is sound in the sense of
`SelectionSound`.
-/

namespace QSB.TS2Instances
open QSB QSB.Soundness QSB.Blocks QSB.TS2

theorem realTs2_side : SideTS2 Tiers.realTs2P Tiers.realTs2R = true := by native_decide

/-- **Headline (M3):** the real-spend TS2 script is sound. -/
theorem realTs2_sound : SelectionSound Tiers.realTs2P Tiers.realTs2R :=
  ts2_family_sound _ _ realTs2_side

theorem ts2_side : SideTS2 Tiers.ts2P Tiers.ts2R = true := by native_decide

/-- The TS2 design of the end-to-end consensus vectors (seed 8) is sound. -/
theorem ts2_sound : SelectionSound Tiers.ts2P Tiers.ts2R := ts2_family_sound _ _ ts2_side

/-- Sanity: tiers outside the family do not satisfy the side condition. -/
theorem others_not_ts2 : SideTS2 Tiers.tierAP Tiers.tierAR = false ∧ SideTS2 Tiers.tierEP Tiers.tierER = false := by
  native_decide

end QSB.TS2Instances

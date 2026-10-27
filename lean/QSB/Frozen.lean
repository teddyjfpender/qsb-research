import QSB.TS2Instances

/-!
# Frozen theorem statements (pinned by hash in `FROZEN.sha256`, checked by `check.sh`)

Each `example` restates a proven theorem's exact type. If a proof file is edited so the theorem
proves something weaker, these fail to typecheck; if this file or a definition the statements depend
on (`Script`, `Bytes`, `Hash`, `Build`, `Soundness`, `Blocks`) is edited, the hash check fails.
-/

open QSB QSB.Soundness QSB.Blocks

/-- M3, family form: every TS2-family design satisfying the decidable side condition is sound. -/
example : ∀ (p : Build.Params) (rnd : Build.Rand), SideTS2 p rnd = true → SelectionSound p rnd :=
  QSB.TS2.ts2_family_sound

/-- M3, headline instance: the script of the real spend accepted by Bitcoin Core. -/
example : SelectionSound Tiers.realTs2P Tiers.realTs2R := QSB.TS2Instances.realTs2_sound

/-- M1: emitted code has the closed-form block structure. -/
example : ∀ (p : Build.Params) (rnd : Build.Rand), SideTS2 p rnd = true →
    parse (Build.build p rnd).script = some ((blocksTS2 p rnd).map CI.instr) :=
  QSB.Blocks.parse_build_TS2

import Lake
open Lake DSL

package qsb where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib QSB where
  roots := #[`QSB]

lean_exe qsbcheck where
  root := `Main
  supportInterpreter := false

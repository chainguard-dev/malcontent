rule clang {
  meta:
	description = "Compiled with LLVM C Compiler"
  strings:
	$llvm_clang = "llvm.clang"
  condition:
	any of them
}

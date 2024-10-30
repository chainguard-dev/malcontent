rule gcc: harmless {
  meta:
    description = "Compiled with GCC (GNU C Compiler)"

  strings:
    $gcc_except_table = "GCC_except_table"
    $gcc_version      = "GCC: "

  condition:
    any of them
}

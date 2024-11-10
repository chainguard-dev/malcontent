rule libdw_override: override {
  meta:
    description     = "libdw.so"
    ptrace_injector = "medium"

  strings:
    $dward = "invalid DWARF"

  condition:
    filesize < 2MB and any of them
}

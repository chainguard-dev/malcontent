rule ap_compiler_override: override {
  meta:
    description                          = "https://github.com/avdaredevil/AP-Compiler"
    Base64_Encoded_Powershell_Directives = "medium"

  strings:
    $ref = "https://github.com/avdaredevil/AP-Compiler"

  condition:
    $ref
}

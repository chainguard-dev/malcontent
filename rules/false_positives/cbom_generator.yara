rule cbom_generator: override {
  meta:
    description         = "/usr/bin/cbom-generator, a cryptographic bill of materials generator"
    proc_d_cmdline      = "medium"
    proc_d_exe_high     = "medium"
    cmd_dev_null_quoted = "medium"

  strings:
    $cipheriq  = /cipheriq\.io/
    $cbom_tool = /cbom:tool:executable/

  condition:
    filesize < 2MB and all of them
}

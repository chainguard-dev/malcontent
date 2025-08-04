rule fastfetch_override: override {
  meta:
    description     = "/usr/bin/fastfetch"
    proc_d_cmdline  = "medium"
    proc_d_exe_high = "medium"

  strings:
    $repo = "https://github.com/fastfetch-cli/fastfetch"

  condition:
    $repo
}

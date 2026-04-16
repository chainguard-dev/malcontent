rule fastfetch_override: override {
  meta:
    description       = "/usr/bin/fastfetch, /usr/bin/flashfetch"
    proc_d_cmdline    = "medium"
    proc_d_exe_high   = "medium"
    multiple_gcc      = "harmless"
    multiple_gcc_high = "medium"

  strings:
    $fastfetch = "fastfetch/packages/%s.txt"
    $repo      = "https://github.com/fastfetch-cli/fastfetch"

  condition:
    filesize < 5MB and any of them
}

rule zsh_persist: medium {
  meta:
    description                     = "access zsh startup files"
    hash_2023_bin_aws_zsh_completer = "426e99f1e8cd00cce9263693d29ceac5b4834f6cf1766cd57b985a440eea2e87"
    hash_2023_bin_aws_zsh_completer = "426e99f1e8cd00cce9263693d29ceac5b4834f6cf1766cd57b985a440eea2e87"
    hash_2023_bin_aws_zsh_completer = "426e99f1e8cd00cce9263693d29ceac5b4834f6cf1766cd57b985a440eea2e87"

  strings:
    $ref      = ".zprofile"
    $ref2     = ".zshrc"
    $ref3     = "/etc/zprofile"
    $ref4     = "/etc/zshrc"
    $not_bash = "POSIXLY_CORRECT"

  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}

rule zsh_logout_persist: high {
  meta:
    description = "Writes to zsh configuration files to persist"

  strings:
    $ref  = ".zlogout"
    $ref2 = "/etc/zlogout"

  condition:
    filesize < 2097152 and any of ($ref*)
}

rule zsh: override {
  meta:
    description        = "zsh"
    zsh_logout_persist = "medium"

  strings:
    $debug = "ZSH_DEBUG_CMD"

  condition:
    filesize > 100KB and filesize < 2MB and all of them
}

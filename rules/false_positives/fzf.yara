rule fzf: override {
  meta:
    description                = "fzf"
    listens_and_executes_shell = "medium"

  strings:
    $fzf = "FZF_DEFAULT" fullword

  condition:
    filesize < 6MB and any of them
}


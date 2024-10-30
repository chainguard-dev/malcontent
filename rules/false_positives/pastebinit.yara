rule pastebinit: override {
  meta:
    description               = "pastebinit user"
    echo_decode_bash_probable = "ignore"
    download_sites            = "medium"

  strings:
    $pb     = "pastebinit" fullword
    $ubuntu = "ubuntu" fullword

  condition:
    filesize < 40KB and all of them
}

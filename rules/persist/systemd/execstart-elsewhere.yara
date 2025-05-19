rule execstart_danger_path_val: high {
  meta:
    ref         = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    description = "Starts from a dangerous-looking path"
    filetypes   = "service"

  strings:
    $awkward = /ExecStart=\/(boot|var|tmp|dev|root)\/[\.\w\-\/]{0,32}/

  condition:
    filesize < 4096 and any of them
}

rule execstart_unexpected_dir_val: medium {
  meta:
    description = "Starts from an unusual path"
    ref         = "https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild/"
    filetypes   = "service"

  strings:
    $execstart           = /ExecStart=\/[\w\/]{1,128}/
    $expected_bin        = "ExecStart=/bin"
    $expected_etc_rc     = "ExecStart=/etc/rc"
    $expected_etc_update = "ExecStart=/etc/update"
    $expected_lib        = "ExecStart=/run"
    $expected_lib_ufw    = "ExecStart=/lib/"
    $expected_nix        = "ExecStart=/nix"
    $expected_sbin       = "ExecStart=/sbin"
    $expected_usr        = "ExecStart=/usr"

  condition:
    filesize < 102400 and $execstart and none of ($expected_*)
}

rule userinfo: medium {
  meta:
    syscall               = "getuid"
    description           = "returns user info for the current process"
    hash_1985_scripts_rsh = "ed706eb208f271abdbbe1cd7cd94cd8c8603f811018d5207a120c718f59652e9"
    hash_1985_scripts_rsh = "ed706eb208f271abdbbe1cd7cd94cd8c8603f811018d5207a120c718f59652e9"

  strings:
    $ref  = "os.userInfo()"
    $ref2 = "os.homedir"

  condition:
    any of them
}

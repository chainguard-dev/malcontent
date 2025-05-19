rule userinfo: medium {
  meta:
    syscall     = "getuid"
    description = "returns user info for the current process"
    filetypes   = "js,ts"

  strings:
    $ref  = "os.userInfo()"
    $ref2 = "os.homedir"

  condition:
    any of them
}

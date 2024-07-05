rule userinfo : medium {
  meta:
    syscall = "getuid"
    description = "returns user info for the current process"
  strings:
    $ref = "os.userInfo()"
  condition:
    any of them
}

rule current_logins: medium {
  meta:
    description = "accesses current logins"

  strings:
    $f_wtmp     = "/var/log/wtmp"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword

  condition:
    any of ($f*) and none of ($not*)
}

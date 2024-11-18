rule historical_logins: medium {
  meta:
    description = "accesses historical login records"

  strings:
    $f_lastlog  = "/var/log/lastlog" fullword
    $f_utmp     = "/var/log/utmp" fullword
    $f_utmpx    = "/var/log/utmpx" fullword
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho   = "_PATH_RWHODIR" fullword
    $not_pam    = "Linux-PAM" fullword

  condition:
    any of ($f*) and none of ($not*)
}

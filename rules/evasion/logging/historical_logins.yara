rule login_records: medium {
  meta:
    description                                                       = "accesses historical login records"
    hash_2023_FontOnLake_45E94ABEDAD8C0044A43FF6D72A5C44C6ABD9378_elf = "f60c1214b5091e6e4e5e7db0c16bf18a062d096c6d69fe1eb3cbd4c50c3a3ed6"
    hash_2023_Lightning_ad16                                          = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
    hash_2023_usr_adxintrin_b                                         = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"

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

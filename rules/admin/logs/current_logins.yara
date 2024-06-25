
rule login_records : medium {
  meta:
    description = "accesses current logins"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
  strings:
    $f_wtmp = "/var/log/wtmp"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho = "_PATH_RWHODIR" fullword
  condition:
    any of ($f*) and none of ($not*)
}

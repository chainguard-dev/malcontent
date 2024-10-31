
rule login_records : medium {
  meta:
    description = "accesses current logins"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2024_static_binaries_make = "15773bb3233a72783bbeffe7d7745012a1afa6f443bc7a230879c30f485333d7"
    hash_2024_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
  strings:
    $f_wtmp = "/var/log/wtmp"
    $not_cshell = "_PATH_CSHELL" fullword
    $not_rwho = "_PATH_RWHODIR" fullword
  condition:
    any of ($f*) and none of ($not*)
}

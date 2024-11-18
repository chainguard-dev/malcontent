rule iot_passwords: high {
  meta:
    description = "contains default passwords from IOT systems"

  strings:
    $f_hikvision         = "hikvision"
    $f_cuadmin           = "CUAdmin"
    $f_assword           = "assword"
    $f_jvbzd             = "jvbzd"
    $f_xmhdipc           = "xmhdipc"
    $f_lnadmin           = "lnadmin"
    $f_123qwe            = "123qwe"
    $f_tsgoingon         = "tsgoingon"
    $not_frequency_list  = "var frequency_lists;frequency_lists={passwords:"
    $not_frequency_list2 = "var frequency_lists;\n\nfrequency_lists = {\n  passwords: "
    $not_onepassword_sdk = "github.com/1password/onepassword-sdk"

  condition:
    3 of ($f*) and none of ($not*)
}

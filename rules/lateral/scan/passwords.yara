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
    $not_frequency_list2 = { 76 61 72 20 66 72 65 71 75 65 6E 63 79 5F 6C 69 73 74 73 3B 0A 0A 66 72 65 71 75 65 6E 63 79 5F 6C 69 73 74 73 20 3D 20 7B 0A 20 20 70 61 73 73 77 6F 72 64 73 3A 20 }
    $not_onepassword_sdk = "github.com/1password/onepassword-sdk"

  condition:
    3 of ($f*) and none of ($not*)
}

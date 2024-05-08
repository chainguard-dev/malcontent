
rule xattr_user : notable {
  meta:
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_CloudMensis_mdworker3 = "273633eee4776aef40904124ed1722a0793e6567f3009cdb037ed0a9d79c1b0b"
  strings:
    $xattr_c = "xattr -c"
    $xattr_d = "xattr -d"
    $xattr_w = "xattr -w"
    $not_xattr_drs_quarantine = "xattr -d -r -s com.apple.quarantine"
    $not_xattr_dr_quarantine = "xattr -d -r com.apple.quarantine"
  condition:
    any of ($xattr*) and none of ($not*)
}

rule xattr_user: medium {
  meta:
    description = "modifies extended filesystem attributes using xattr"

  strings:
    $xattr_c                  = "xattr -c"
    $xattr_d                  = "xattr -d"
    $xattr_w                  = "xattr -w"
    $not_xattr_drs_quarantine = "xattr -d -r -s com.apple.quarantine"
    $not_xattr_dr_quarantine  = "xattr -d -r com.apple.quarantine"

  condition:
    any of ($xattr*) and none of ($not*)
}

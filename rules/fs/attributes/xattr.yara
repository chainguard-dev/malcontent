rule xattr_user: medium {
  meta:
    description = "modifies extended filesystem attributes using xattr"

  strings:
    $xattr_c                  = "xattr -c "
    $xattr_d                  = "xattr -d "
    $xattr_w                  = "xattr -w "
    $not_xattr_drs_quarantine = "xattr -d -r -s com.apple.quarantine"
    $not_xattr_dr_quarantine  = "xattr -d -r com.apple.quarantine"

  condition:
    // both $not spellings start with "xattr -d ", so count past them instead of
    // exempting the file: a de-quarantine call no longer hides other xattr use
    $xattr_c or $xattr_w or #xattr_d > #not_xattr_drs_quarantine + #not_xattr_dr_quarantine
}

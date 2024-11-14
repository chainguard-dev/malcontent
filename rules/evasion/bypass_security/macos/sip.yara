rule csrutil_user: medium {
  meta:
  strings:
    $csrutil     = "csrutil"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_program = "@(#)PROGRAM:"
    $not_verbose = "CSRUTIL_VERBOSE"
    $not_mdm     = "com.kandji.profile.mdmprofile"

  condition:
    $csrutil and none of ($not_*)
}

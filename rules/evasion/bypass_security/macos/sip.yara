rule csrutil_user: medium {
  meta:
    description = "uses csrutil"

  strings:
    $csrutil = "csrutil"

    $notgrp_apple_private = "/System/Library/PrivateFrameworks/"
    $notgrp_apple_program = "@(#)PROGRAM:"

    $not_verbose = "CSRUTIL_VERBOSE"
    $not_mdm     = "com.kandji.profile.mdmprofile"

  condition:
    // the PrivateFrameworks path and the SCCS what-string only identify an
    // Apple-shipped binary together; either alone also turns up in malware
    $csrutil and not all of ($notgrp_apple*) and none of ($not_verbose, $not_mdm)
}

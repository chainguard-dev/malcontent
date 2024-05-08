
rule csrutil_user : medium {
  meta:
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_DazzleSpy_softwareupdate = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"
  strings:
    $csrutil = "csrutil"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_program = "@(#)PROGRAM:"
    $not_verbose = "CSRUTIL_VERBOSE"
    $not_mdm = "com.kandji.profile.mdmprofile"
  condition:
    $csrutil and none of ($not_*)
}

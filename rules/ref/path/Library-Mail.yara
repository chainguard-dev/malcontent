
rule macos_library_mail_ref : notable {
  meta:
    hash_2022_CloudMensis_WindowServer = "317ce26cae14dc9a5e4d4667f00fee771b4543e91c944580bbb136e7fe339427"
    hash_2022_CloudMensis_WindowServer_2 = "b8a61adccefb13b7058e47edcd10a127c483403cf38f7ece126954e95e86f2bd"
    hash_2022_DazzleSpy_softwareupdate = "f9ad42a9bd9ade188e997845cae1b0587bf496a35c3bffacd20fefe07860a348"
  strings:
    $mail = "Library/Mail"
    $not_private = "/System/Library/PrivateFrameworks/"
    $not_apple = "Apple Inc."
    $not_sandbox_profile = "sandbox profile"
  condition:
    $mail and none of ($not*)
}

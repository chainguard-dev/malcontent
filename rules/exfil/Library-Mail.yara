rule macos_library_mail_ref: medium {
  meta:




  strings:
    $mail                = "Library/Mail"
    $not_private         = "/System/Library/PrivateFrameworks/"
    $not_apple           = "Apple Inc."
    $not_sandbox_profile = "sandbox profile"

  condition:
    $mail and none of ($not*)
}

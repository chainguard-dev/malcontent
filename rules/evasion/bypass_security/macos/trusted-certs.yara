rule trusted_cert_manipulator: high {
  meta:
    hash_2017_MacOS_AppStore = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"

  strings:
    $security         = "security"
    $add_trusted_cert = "add-trusted-cert"
    $not_certtool     = "PROGRAM:certtool"
    $not_private      = "/System/Library/PrivateFrameworks"

  condition:
    $security and $add_trusted_cert and none of ($not*)
}

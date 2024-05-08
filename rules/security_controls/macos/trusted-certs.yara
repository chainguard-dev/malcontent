
rule trusted_cert_manipulator : suspicious {
  strings:
    $security = "security"
    $add_trusted_cert = "add-trusted-cert"
    $not_certtool = "PROGRAM:certtool"
    $not_private = "/System/Library/PrivateFrameworks"
  condition:
    $security and $add_trusted_cert and none of ($not*)
}

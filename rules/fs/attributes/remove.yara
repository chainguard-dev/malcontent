rule remove_xattr: medium {
  meta:
    description = "remove an extended file attribute value"
    ref         = "https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/removexattr.2.html"

  strings:
    $ref = "removexattr" fullword

  condition:
    any of them
}

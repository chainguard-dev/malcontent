rule download: medium {
  meta:
    description = "download files"

  strings:
    $ref    = /[a-zA-Z\-_ ]{0,16}download[a-zA-Z\-_ ]{0,16}/ fullword
    $ref2   = /[a-zA-Z\-_ ]{0,16}DOWNLOAD[a-zA-Z\-_ ]{0,16}/ fullword
    $ref3   = /[a-zA-Z\-_ ]{0,16}Download[a-zA-Z\-_ ]{0,16}/ fullword
    $ref4   = "Dwnld" fullword
    $not_be = "be downloaded"

  condition:
    any of ($ref*) and none of ($not*)
}

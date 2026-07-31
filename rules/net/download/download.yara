rule download: medium {
  meta:
    description = "download files"

  strings:
    $ref  = /[a-zA-Z\-_ ]{0,16}download[a-zA-Z\-_ ]{0,16}/ fullword
    $ref2 = /[a-zA-Z\-_ ]{0,16}DOWNLOAD[a-zA-Z\-_ ]{0,16}/ fullword
    $ref3 = /[a-zA-Z\-_ ]{0,16}Download[a-zA-Z\-_ ]{0,16}/ fullword
    $ref4 = "Dwnld" fullword
    $word = "download"

    $not_be = "be downloaded"

  condition:
    // "be downloaded" is itself a $ref match, so one doc-string phrase used to hide
    // every other download reference in the file. $ref carries up to 16 characters
    // of context and yields several matches per occurrence, so it cannot be counted
    // directly; count the bare word instead. Each "be downloaded" contributes
    // exactly one, so fire only on a lowercase occurrence it does not account for.
    // The other spellings are case-sensitive and "be downloaded" cannot explain
    // them, so they stand on their own.
    $ref2 or $ref3 or $ref4 or ($ref and #word > #not_be)
}

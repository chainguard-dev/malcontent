rule webhook: medium {
  meta:
    description = "supports webhooks"

  strings:
    $ref = /[a-zA-Z]{0,16}[wW]eb[hH]ook[\w]{0,32}/ fullword

  condition:
    any of them
}

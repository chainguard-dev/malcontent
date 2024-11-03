rule ebe: critical {
  meta:
    description = "highly obfuscated javascript (eBe)"
    filetypes   = "javascript"

  strings:
    $function   = "function("
    $charCodeAt = "charCodeAt"

    $ref = /eBe\(-\d{1,3}\)/

  condition:
    filesize < 5MB and $function and $charCodeAt and #ref > 10
}

rule ebe_generic: high {
  meta:
    description = "highly obfuscated javascript"
    filetypes   = "javascript"

  strings:
    $function   = "function("
    $charCodeAt = "charCodeAt"

    $ref  = /\w\[\w{1,3}\(\d{1,3}\)\]=\w{1,3}\(\d{1,3}\),e\[\w{1,3}\(\d{1,3}\)\]/
    $ref2 = /\w\[\w{1,3}\(\d{1,3}\)\]\&\w{1,3}\(\d{1,3}\)\),\w\[\w{1,3}\(\d{1,3}\)\]/
    $ref3 = /\>\w{1,3}\(\d{1,3}\)\);\w\[\w{1,3}\(\d{1,3}\)\]\=/

  condition:
    filesize < 5MB and #function and $charCodeAt and (#ref > 5 or #ref2 > 5 or #ref3 > 5)
}


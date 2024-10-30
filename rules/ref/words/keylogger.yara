rule keylogger: medium {
  meta:
    description = "references a 'keylogger'"

  strings:
    $ref = /[\w\_]{0,64}[kK]eylogger[\w\_]{0,64}/ fullword

  condition:
    any of them
}

rule start_keylogger: high {
  meta:
    description = "references starting a 'keylogger'"

  strings:
    $ref = /start[\w\_]{0,8}[kK]eylogger[\w\_]{0,64}/ fullword

  condition:
    any of them
}

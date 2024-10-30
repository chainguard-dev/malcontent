rule casing_obfuscation: medium windows {
  meta:
    description = "unusual casing obfuscation"
    author      = "Florian Roth"

  strings:
    $ref = /  (sEt|SEt|SeT|sET|seT)  / ascii wide

  condition:
    filesize < 16777216 and any of them
}

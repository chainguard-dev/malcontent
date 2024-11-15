rule html: medium {
  meta:
    description = "Contains HTML content"

  strings:
    $ref  = "<html>"
    $ref2 = "<img src>"
    $ref3 = "<a href>"
    $ref4 = "DOCTYPE html"
    $ref5 = "<html lang"

  condition:
    any of them
}

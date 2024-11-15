rule pgrep: medium {
  meta:
    description = "Finds program in process table"

  strings:
    $val = /pgrep[ \w\$]{0,32}/ fullword

  condition:
    $val
}

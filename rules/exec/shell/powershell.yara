rule powershell: medium {
  meta:
    description = "runs powershell scripts"

  strings:
    $val             = /powershell[ \w\-]{0,32}/ fullword
    $val2            = "power-shell"
    $val3            = "power_shell"
    $val4            = "powerShell"
    $not_completions = "powershell_completion"

  condition:
    any of ($val*) and none of ($not*)
}

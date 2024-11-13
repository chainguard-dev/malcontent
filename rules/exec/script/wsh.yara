import "math"

rule WScript_CreateObject: high windows {
  meta:
    description = "Create a Windows Scripting Host (WSH) object"

  strings:
    $ExecShell = "WScript.CreateObject(\"WScript.Shell\")"

  condition:
    any of them
}

rule WScript: medium windows {
  meta:
    description = "Create a Windows Scripting Host (WSH) object"

  strings:
    $WScript = "WScript" fullword
    $Shell   = "Shell" fullword

  condition:
    math.max(@WScript, @Shell) - math.min(@WScript, @Shell) <= 4500
}

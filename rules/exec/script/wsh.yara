import "math"

rule WScript: medium windows {
  meta:
    description = "Accesses a Windows Scripting Host (WSH) object"

  strings:
    $WScript = "WScript" fullword

  condition:
    filesize < 2MB and any of them
}

rule WScript_CreateObject: high windows {
  meta:
    description = "Create a Windows Scripting Host (WSH) shell object"

  strings:
    $ExecShell = "WScript.CreateObject(\"WScript.Shell\")"

  condition:
    any of them
}

rule WScript_Shell: medium windows {
  meta:
    description = "Create a Windows Scripting Host (WSH) shell object"

  strings:
    $WScript = "WScript" fullword
    $Shell   = "Shell" fullword

  condition:
    math.max(@WScript, @Shell) - math.min(@WScript, @Shell) <= 4500
}

rule WScript_Obfuscated: critical windows {
  meta:
    description = "obfuscated access to a Windows Scripting Host"

  strings:
    $WScript      = /WScript\./ fullword
    $fromCharCode = /fromCharCode\(\d+/
    $math         = /fromCharCode\(\d+\^/

  condition:
    $WScript and ((#fromCharCode > 3) or $math)
}

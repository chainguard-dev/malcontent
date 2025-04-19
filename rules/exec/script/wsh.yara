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

rule WScript_char_obfuscation: critical windows {
  meta:
    description = "obfuscated access to a Windows Scripting Host"

  strings:
    $WScript      = /WScript[\.\[]/
    $fromCharCode = /fromCharCode\(\d+/
    $fromCharCodeMath         = /fromCharCode\(\d+\^/
    $charCodeAt = /charCodeAt/

  condition:
    filesize < 512KB and $WScript and ((#fromCharCode > 3) or (#charCodeAt > 3) or $fromCharCodeMath)
}


rule WScript_hex: critical windows {
  meta:
    description = "obfuscated access to a Windows Scripting Host"

  strings:
    $hex = /WScript\[\w{0,2}\(\w{0,8}\)\]/

  condition:
    filesize < 2MB and $hex
}

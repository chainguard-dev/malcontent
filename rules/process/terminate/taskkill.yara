rule taskkill: medium windows {
  meta:
    description = "kills tasks and/or processes"

  strings:
    $ref  = "taskkill" fullword
    $ref2 = "TASKKILL" fullword

  condition:
    any of them
}

rule taskkill_force: high windows {
  meta:
    description = "forcibly kills programs"

  strings:
    $ref  = /taskkill \/IM .{0,32}\.exe \/F/
    $ref2 = /TASKKILL \/IM .{0,32}\.exe \/F/

  condition:
    any of them
}


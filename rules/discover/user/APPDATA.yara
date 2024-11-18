rule APPDATA: windows low {
  meta:
    description = "Looks up the application data directory for the current user"

  strings:
    $ref = "APPDATA" fullword

  condition:
    all of them
}

rule APPDATA_microsoft: windows medium {
  meta:
    description = "Looks up the 'Microsoft' application data directory for the current user"

  strings:
    $ref  = "APPDATA" fullword
    $ref2 = "'Microsoft'"

  condition:
    all of them
}

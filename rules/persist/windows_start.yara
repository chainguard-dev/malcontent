rule autorun: high {
  meta:
    description = "Accesses Windows Start Menu"

  strings:
    $ref  = "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
    $ref2 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"

  condition:
    any of them
}

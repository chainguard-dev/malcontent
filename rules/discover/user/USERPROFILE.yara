rule USERPROFILE: windows low {
  meta:
    description = "Looks up the user profile directory for the current user"

  strings:
    $ref = "USERPROFILE" fullword

  condition:
    all of them
}

rule USERPROFILE_Desktop: windows medium {
  meta:
    description = "Looks up the Desktop directory for the current user"

  strings:
    $ref  = "USERPROFILE" fullword
    $ref2 = "Desktop"

  condition:
    all of them
}

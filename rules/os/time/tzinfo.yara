rule tzinfo {
  meta:
    description = "Uses timezone information"

  strings:
    $tzinfo = "tzinfo" fullword
    $tzInfo = "tzInfo" fullword
    $tzdata = "tzdata" fullword

  condition:
    any of them
}


rule hardcoded_analytics: high {
  meta:
    description = "Contains hardcoded Google Analytics ID"

  strings:
    $ref  = /UA-[\d]{5,9}-\d{1,3}/ fullword
    $ref2 = "analytics"

  condition:
    all of them
}

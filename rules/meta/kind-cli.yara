rule usage : harmless {
  strings:
    $usage = "usage:" fullword
  condition:
 	any of them
}
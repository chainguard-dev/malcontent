rule ruby_calls_itself: medium {
  meta:
    description = "Ruby program executes Ruby subprocess"

  strings:
    $system = /system\(['"]ruby[\w \.]{0,16}/

  condition:
    any of them
}

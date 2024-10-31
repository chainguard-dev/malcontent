rule png: medium {
  strings:
    $eval = "<img src=\"data:image/png;(.*)\""

  condition:
    any of them
}

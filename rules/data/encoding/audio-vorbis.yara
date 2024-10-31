rule vorbisdsp: harmless {
  strings:
    $vorbisdsp = "vorbisdsp"

  condition:
    any of them
}

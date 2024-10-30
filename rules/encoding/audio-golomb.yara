rule golumb_vlc: harmless {
  strings:
    $golomb_vlc = "golomb_vlc"

  condition:
    any of them
}

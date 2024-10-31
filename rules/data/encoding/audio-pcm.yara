rule pcm: harmless {
  strings:
    $pcm_mulaw     = "pcm_mulaw" fullword
    $pcm_alaw      = "pcm_mulaw" fullword
    $pcm_s8_planar = "pcm_s8_planar" fullword

  condition:
    any of them
}


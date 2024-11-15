rule ngrok: medium {
  meta:
    ref         = "https://github.com/ditekshen/detection/blob/e6579590779f62cbe7f5e14b5be7d77b2280f516/yara/indicator_high.yar#L1001"
    description = "References known file hosting site"

  strings:
    $d_pastebin = "ngrok.io"

  condition:
    any of ($d_*)
}

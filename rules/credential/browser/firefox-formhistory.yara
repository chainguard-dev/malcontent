rule firefox_history: high {
  meta:
    description              = "access Firefox form history, which contains passwords"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"

    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"

  strings:
    $firefox      = "Firefox"
    $formhist     = "formhistory.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"

  condition:
    filesize < 100MB and all of ($f*) and none of ($not*)
}

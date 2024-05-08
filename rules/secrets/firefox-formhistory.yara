
rule firefox_history : high {
  meta:
    description = "access Firefox form history, which contains passwords"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
    hash_2023_Downloads_e6b6 = "e6b6cf40d605fc7a5e8ba168a8a5d8699b0879e965d2b803e29b87926cba861f"
  strings:
    $firefox = "Firefox"
    $formhist = "formhistory.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"
  condition:
    all of ($f*) and none of ($not*)
}

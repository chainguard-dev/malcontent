
rule firefox_cookies : suspicious {
  meta:
    description = "access Firefox cookies"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2023_Downloads_589d = "589dbb3f678511825c310447b6aece312a4471394b3bc40dde6c75623fc108c0"
    hash_2023_Downloads_Brawl_Earth = "fe3ac61c701945f833f218c98b18dca704e83df2cf1a8994603d929f25d1cce2"
  strings:
    $firefox = "Firefox"
    $fcookie = "cookies.sqlite"
    $not_chromium = "CHROMIUM_TIMESTAMP"
  condition:
    all of ($f*) and none of ($not*)
}

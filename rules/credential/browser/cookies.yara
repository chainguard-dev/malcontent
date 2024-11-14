rule macos_cookies: high macos {
  meta:
    ref         = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
    description = "access macOS Cookie files"

  strings:
    $ref         = "/Library/Cookies"
    $ref2        = ".binarycookies"
    $not_private = "com.apple.private."

  condition:
    any of ($ref*) and none of ($not*)
}

rule browser_cookies: high {
  meta:
    description = "accesses browser cookies"
    ref         = "https://pypi.org/project/pycookiecheat/"

  strings:
    $ref  = "pycookiecheat"
    $ref2 = "browserutils/kooky"

  condition:
    all of them
}

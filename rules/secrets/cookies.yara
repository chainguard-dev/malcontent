rule macos_cookies_val : suspicious {
  meta:
    ref = "https://www.sentinelone.com/blog/macos-malware-2023-a-deep-dive-into-emerging-trends-and-evolving-techniques/"
	description = "access macOS Cookie files"
  strings:
	$ref = "/Library/Cookies"
	$ref2 = ".binarycookies"
  condition:
    any of them
}

rule browser_cookies : suspicious {
  meta:
	description = "accesses browser cookies"
    ref = "https://pypi.org/project/pycookiecheat/"
  strings:
	$ref = "pycookiecheat"
	$ref2 = "browserutils/kooky"
  condition:
    all of them
}

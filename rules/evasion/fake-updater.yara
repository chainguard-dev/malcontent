
rule fake_chrome_update : high {
  meta:
	description = "May fake being a Chrome update"
  strings:
	$ref = "GoogleChromeUpdate"
  condition:
	$ref
}
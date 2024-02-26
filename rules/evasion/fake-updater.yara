
rule fake_chrome_update : suspicious {
  meta:
	description = "May fake being a Chrome update"
  strings:
	$ref = "GoogleChromeUpdate"
  condition:
	$ref
}
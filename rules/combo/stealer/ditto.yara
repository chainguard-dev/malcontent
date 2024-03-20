
rule crypto_stealer : suspicious {
  meta:
	description = "makes HTTP connections and creates archives using ditto"
  strings:
	$http = "http"
	$http_POST = /POST[ \/\w]{0,32}/

	$w_ditto = /ditto -[\w\-\/ ]{0,32}/
	$w_zip = /[\w\-\/ ]{0,32}\.zip/
  condition:
	any of ($http*) and 2 of ($w*)
}

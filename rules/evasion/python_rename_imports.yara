rule rename_requests : medium {
  meta:
    description = "imports 'requests' library and gives it another name"
  strings:
	$ref = /import requests as \w{0,64}/
  condition:
	filesize < 65535 and all of them
}

rule rename_requests_2char : high {
  meta:
    description = "imports 'requests' library and gives it a two-letter name"
  strings:
	$ref = /import requests as \w{2}/
  condition:
	filesize < 65535 and all of them
}

rule rename_os : high {
  meta:
    description = "imports 'os' library and gives it another name"
  strings:
	$ref = /import os as \w{0,64}/
	$not_underscore = "import os as _os"
	$not_gos = "import os as gos"
  condition:
	filesize < 65535 and $ref and none of ($not*)
}

rule rename_marshal : critical {
  meta:
    description = "imports 'marshal' library and gives it another name"
  strings:
	$ref = /import marshal as \w{0,64}/
  condition:
	filesize < 65535 and all of them
}

rule rename_base64 : critical {
  meta:
    description = "imports 'base64' library and gives it another name"
  strings:
	$ref = /import base64 as \w{0,64}/
  condition:
	filesize < 65535 and all of them
}

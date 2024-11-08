rule http_post: medium {
  meta:
    pledge                       = "inet"
    description                  = "submits content to websites"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2023_0xShell_adminer    = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_root       = "3baa3bfaa6ed78e853828f147c3747d818590faee5eecef67748209dd3d92afb"

  strings:
    $POST         = "POST"
    $h_HTTP       = "HTTP"
    $http         = "http"
    $http_content = "Content-Type"

  condition:
    $POST and any of ($h*)
}

rule axios_post: medium {
  meta:
    description = "posts content to websites"
    filetype    = "js,ts"

  strings:
    $axios = "axios" fullword
    $post  = ".post("

  condition:
    filesize < 4MB and all of them
}

rule axios_post_hardcoded: high {
  meta:
    description = "posts content to hardcoded HTTP site"
    filetype    = "js,ts"

  strings:
    $axios = "axios" fullword
    $post  = /\w{1,12}.post\(\'https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/

  condition:
    filesize < 6MB and all of them
}

rule form_data_reference: medium {
  meta:
    description                  = "submits form content to websites"
    hash_2019_restclient_payload = "97b4859cd7ff37977e76079c1b2dbe80adcbe80893afc6fb9876cac8d2373d10"
    hash_2019_spec_payload_spec  = "fe743cdfe68aa357cf60fc55704e20d49fd713038878dca427a47285b4bfa493"
    hash_2023_Downloads_016a     = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"

  strings:
    $f_content_dispo_name = "Content-Disposition: form-data; name=.{0,32}\""
    $f_multipart          = "multipart/form-data; boundary="

  condition:
    any of ($f_*)
}


rule form_upload_hardcoded_name: high {
  meta:
    description                  = "submits form content to websites as a hardcoded filename"

  strings:
	$ref = /Content-Disposition: form-data; name="upload"; filename="[\w\.]{1,12}"/
  condition:
    any of them
}
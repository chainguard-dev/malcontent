rule http_post: medium {
  meta:
    pledge      = "inet"
    description = "submits content to websites"

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
    description = "submits form content to websites"

  strings:
    $f_content_dispo_name = "Content-Disposition: form-data; name=.{0,32}\""
    $f_multipart          = "multipart/form-data; boundary="

  condition:
    any of ($f_*)
}

rule form_upload_hardcoded_name: high {
  meta:
    description = "submits form content to websites as a hardcoded filename"

  strings:
    $ref = /Content-Disposition: form-data; name="upload"; filename="[\w\.]{1,12}"/

  condition:
    any of them
}

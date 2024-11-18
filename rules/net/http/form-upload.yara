rule http_form_upload: medium {
  meta:
    pledge      = "inet"
    description = "upload content via HTTP form"

  strings:
    $content_form = "application/x-www-form-urlencoded"
    $content_json = "application/json"
    $POST         = "POST" fullword
    $POST2        = "post" fullword

  condition:
    any of ($POST*) and any of ($content*)
}

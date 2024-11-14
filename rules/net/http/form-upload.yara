rule http_form_upload: medium {
  meta:
    pledge                    = "inet"
    description               = "upload content via HTTP form"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"

    hash_2019_lib_restclient = "c9b67d3d9ef722facd1abce98bd7d80cec1cc1bb3e3a52c54bba91f19b5a6620"

  strings:
    $content_form = "application/x-www-form-urlencoded"
    $content_json = "application/json"
    $POST         = "POST" fullword

  condition:
    $POST and any of ($content*)
}

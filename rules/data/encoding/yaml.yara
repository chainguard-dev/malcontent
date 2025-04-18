rule yaml_decode: low {
  meta:
    description = "Decodes YAML content"

  strings:
    $yamld = "YAMLDecode"
    $yu    = "yaml.Unmarshal"
    $yp    = "YAML.parse"
    $yl    = "yaml.load"

  condition:
    any of them
}

rule yaml_unsafe_decode: medium {
  meta:
    description = "Unsafe decoding of YAML content (can execute arbitrary code)"

  strings:
    $yaml_load = "yaml.load("

  condition:
    filesize < 256KB and any of them
}

rule yaml_unsafe_decode_remote: high {
  meta:
    description = "Unsafe decoding of remote YAML content (can execute arbitrary code)"

  strings:
    $yaml_load = "yaml.load("

    $f_requests      = "requests.get" fullword
    $f_requests_post = "requests.post" fullword
    $f_urllib        = "urllib.request" fullword
    $f_urlopen       = "urlopen" fullword

  condition:
    filesize < 256KB and $yaml_load and any of ($f*)
}

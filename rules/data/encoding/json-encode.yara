rule JSONEncode {
  meta:
    description = "encodes JSON"

  strings:
    $jsone = "JSONEncode"
    $npm   = "JSON.stringify"

  condition:
    any of them
}

rule MarshalJSON: harmless {
  meta:
    description = "encodes JSON"

  strings:
    $json = "MarshalJSON"

  condition:
    any of them
}

rule json_dumps: low {
  meta:
    description = "encodes JSON"
    filetypes   = "py"

  strings:
    $jsone   = "json" fullword
    $marshal = "dumps" fullword
    $import  = "import" fullword

  condition:
    filesize < 8KB and all of them
}

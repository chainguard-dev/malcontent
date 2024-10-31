// none because all binaries include it
rule jsondecode {
  meta:
    description = "Decodes JSON messages"

  strings:
    $jsond = "JSONDecode"
    $ju    = "json.Unmarshal"
    $jp    = "JSON.parse"
    $jl    = "json.loads"

  condition:
    any of them
}

// none because all Go binaries include it
rule unmarshal_json: harmless {
  meta:
    description = "Decodes JSON messages"

  strings:
    $unmarshal = "UnmarshalJSON"

  condition:
    any of them
}

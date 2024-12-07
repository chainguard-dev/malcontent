import "math"

rule generic_key_48_192: medium {
  meta:
    description = "possible key material"

  strings:
    $key = /[a-zA-Z0-9]{48,192}/ fullword

  condition:
    filesize < 20MB and $key and math.entropy(@key, @key + 47) > 4.5
}

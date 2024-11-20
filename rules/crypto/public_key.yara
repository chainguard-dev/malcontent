rule public_key: low {
  meta:
    description = "references a 'public key'"

  strings:
    $public_key = /[pP]ublic[\._ -]{0,2}[kK]ey/

  condition:
    any of them
}

rule verifies_public_key: medium {
  meta:
    description = "verifies a 'public key'"

  strings:
    $public_key = /[vV]erify\._ -]{0,2}[pP]ublic[_ -]{0,2}[kK]ey/

  condition:
    any of them
}


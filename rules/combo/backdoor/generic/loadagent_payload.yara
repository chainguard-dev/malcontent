
rule load_agent_with_payload : suspicious {
  meta:
    hash_2020_FinSpy_caglayan_macos = "d20fcffe09bcfbcd5b69f8fa506a614d1580fce14d23abe288e632e83936095a"
    hash_2020_FinSpy_installer = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"
    hash_2020_finspy_logind_installer = "ac414a14464bf38a59b8acdfcdf1c76451c2d79da0b3f2e53c07ed1c94aeddcd"
  strings:
    $loadAgent = "loadAgent"
    $payload = "payload"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    $payload and $loadAgent and none of ($not*)
}
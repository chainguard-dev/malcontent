rule load_agent_with_payload: high {
  meta:
    hash_2020_FinSpy_installer                 = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"
    hash_2018_org_logind_ctp_archive_installer = "ac414a14464bf38a59b8acdfcdf1c76451c2d79da0b3f2e53c07ed1c94aeddcd"

  strings:
    $loadAgent   = "loadAgent"
    $payload     = "payload"
    $not_private = "/System/Library/PrivateFrameworks/"

  condition:
    $payload and $loadAgent and none of ($not*)
}

rule systemd_short_description {
  meta:
	description = "Short or no description"
    hash_2021_malxmr_install_sh = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2023_articles_https_pberba_github_io_security_2022_02_07_linux_threat_hunting_for_persistence_systemd_generators = "8c227f67a16162ffd5b453a478ced2950eba4cbe3b004c5cc935fb9551dc2289"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
  strings:
    $execstart = "ExecStart="
    $short_desc = /Description=\w{,4}/ fullword
  condition:
    filesize < 4KB and all of them
}

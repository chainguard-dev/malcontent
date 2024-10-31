rule hardcoded_analytics: high {
  meta:
    description                                                                                                           = "Contains hardcoded Google Analytics ID"
    hash_2023_anarchy                                                                                                     = "1a6f8d758c6e569109a021c01cc4a5e787a9c876866c0ce5a15f07f266ec8059"
    hash_2023_misc_mktmpio                                                                                                = "f6b7984c76d92390f5530daeacf4f77047b176ffb8eaf5c79c74d6dd4d514b2b"
    hash_2023_articles_https_pberba_github_io_security_2022_02_07_linux_threat_hunting_for_persistence_systemd_generators = "8c227f67a16162ffd5b453a478ced2950eba4cbe3b004c5cc935fb9551dc2289"

  strings:
    $ref  = /UA-[\d]{5,9}-\d{1,3}/ fullword
    $ref2 = "analytics"

  condition:
    all of them
}

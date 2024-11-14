rule var_run_subfolder: medium {
  meta:
    description              = "references subfolder within /var/run"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"

    hash_2023_Linux_Malware_Samples_00ae = "00ae07c9fe63b080181b8a6d59c6b3b6f9913938858829e5a42ab90fb72edf7a"

  strings:
    $var_run_folder  = /\/var\/run\/[\w\.\-]{0,32}\//
    $not_var_run_run = "/var/run/run"
    $not_named       = "/var/run/named"
    $not_racoon      = "/var/run/racoon"
    $not_private     = "/Library/PrivateFrameworks"

  condition:
    $var_run_folder and none of ($not*)
}

rule var_run_subfolder: medium {
  meta:
    description = "references subfolder within /var/run"

  strings:
    $var_run_folder  = /\/var\/run\/[\w\.\-]{0,32}\//
    $not_var_run_run = "/var/run/run"
    $not_named       = "/var/run/named"
    $not_racoon      = "/var/run/racoon"
    $not_private     = "/Library/PrivateFrameworks"

  condition:
    $var_run_folder and none of ($not*)
}

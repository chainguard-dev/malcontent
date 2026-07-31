rule var_run_subfolder: medium {
  meta:
    description = "references subfolder within /var/run"

  strings:
    // trailing slash added so each accepted spelling costs exactly one
    // $var_run_folder match, which the counts below rely on
    $var_run_folder  = /\/var\/run\/[\w\.\-]{0,32}\//
    $not_var_run_run = "/var/run/run/"
    $not_named       = "/var/run/named/"
    $not_racoon      = "/var/run/racoon/"
    $not_private     = "/Library/PrivateFrameworks"

  condition:
    // $var_run_folder matches the three accepted subfolders itself, so require a
    // subfolder beyond them rather than letting one accepted path disarm the rule;
    // /Library/PrivateFrameworks marks an Apple system framework independently of
    // any /var/run spelling, so it stays an absolute suppressor
    #var_run_folder > #not_var_run_run + #not_named + #not_racoon and not $not_private
}

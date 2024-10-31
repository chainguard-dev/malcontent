rule sethostname {
  strings:
    $sethostname = "sethostname"

  condition:
    any of them
}

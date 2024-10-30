rule google_docs_user: high {
  strings:
    $writely   = "www.google.com/accounts/ServiceLogin?service=writely"
    $guploader = "x-guploader-client-info: mechanism=scotty"

  condition:
    any of them
}


rule google_docs_user : suspicious {
  strings:
    $writely = "www.google.com/accounts/ServiceLogin?service=writely"
    $guploader = "x-guploader-client-info: mechanism=scotty"
    $docs_google_com = "docs.google.com"
  condition:
    any of them
}

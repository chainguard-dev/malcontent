rule google_metadata {
  meta:
    description = "Includes the token required to use the Google Cloud Platform metadata server"

  strings:
    $ref = "Metadata-Flavor"

  condition:
    any of them
}


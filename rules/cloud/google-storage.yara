rule go_import {
  meta:
    description = "Capable of using Google Cloud Storage (GCS)"

  strings:
    $ref = "cloud.google.com/go/storage" fullword

  condition:
    any of them
}


rule curl_easy: medium {
  meta:
    description = "uses curl_easy for HTTP transfers, possibly to a C2"

  strings:
    $curl = "curl_easy_init" fullword

  condition:
    filesize < 1MB and all of them
}


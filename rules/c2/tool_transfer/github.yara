rule github_raw_usercontent: medium {
  meta:
    description = "References raw.githubusercontent.com"

  strings:
    $raw_github = "raw.githubusercontent.com"
    $not_node   = "NODE_DEBUG_NATIVE"

  condition:
    $raw_github and $not_node
}

rule github_raw_user: medium {
  meta:
    description = "downloads raw content from GitHub"

  strings:
    $github     = "github.com"
    $raw_master = "raw/master"
    $raw_main   = "raw/main"
    $not_node   = "NODE_DEBUG_NATIVE"

  condition:
    $github and any of ($raw*) and none of ($not*)
}

rule github_attachment: high {
  meta:
    ref         = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/redline-stealer-a-novel-approach/"
    description = "references a GitHub comment attachment"

  strings:
    $ref = /github\.com\/\w{0,32}\/\w{0,32}\/files\/\d{0,16}\/[\w\.\-]{0,64}/

  condition:
    all of them
}

rule github_blob: medium {
  meta:
    description = "references GitHub blob"

  strings:
    $ref = /api\.github\.com\/repos\/\w{1,32}\/\w{1,32}\/git\/blobs\/[\w%\{\}\/]{0,64}/

  condition:
    any of them
}

rule chmod_github_attachment: high {
  meta:
    description = "downloads program from GitHub blob"

  strings:
    $ref            = /api\.github\.com\/repos\/\w{1,32}\/\w{1,32}\/git\/blobs\/[\w%\{\}\/]{0,64}/
    $fetch_curl     = "curl"
    $fetch_wget     = "wget"
    $fetch_requests = /[a-z]{2,8}\.get/ fullword
    $chmod          = "chmod"

  condition:
    $ref and $chmod and any of ($fetch*)
}

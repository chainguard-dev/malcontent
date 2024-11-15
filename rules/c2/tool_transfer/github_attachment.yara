rule github_attachment: high {
  meta:
    ref         = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/redline-stealer-a-novel-approach/"
    description = "references a GitHub comment attachment"

  strings:
    $ref = /github\.com\/\w{0,32}\/\w{0,32}\/files\/\d{0,16}\/[\w\.\-]{0,64}/

  condition:
    all of them
}

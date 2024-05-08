
rule github_comment_attachment : high {
  meta:
    ref = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/redline-stealer-a-novel-approach/"
    description = "references a GitHub comment attachment, sometimes used to distribute malware"
    hash_2024_synthetic_github_attach_fetch = "fd2f0e9cf4288d2be6b22bd0c6e8a5eb99777939c9b2278ecf89f5b8ad536719"
  strings:
    $ref = /github\.com\/\w{0,32}\/\w{0,32}\/files\/\d{0,16}\/[\w\.\-]{0,64}/
  condition:
    all of them
}

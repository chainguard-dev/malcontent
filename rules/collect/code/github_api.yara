rule github_api_user {
  meta:
    description = "access GitHub API"

  strings:
    $ref  = "google/go-github"
    $ref2 = "api.github.com"

  condition:
    any of them
}

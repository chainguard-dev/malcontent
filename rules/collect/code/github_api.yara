rule github_api_user {
  meta:
	description = "access GitHub API"
  strings:
	$ref = "google/go-github"
  condition:
	any of them
}
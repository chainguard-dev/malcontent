rule github_api_user {
  meta:
	description = "Accesses the GitHub API"
  strings:
	$ref = "google/go-github"
  condition:
	any of them
}
rule gitaly : override {
  meta:
    description = "gitaly"
    linux_multi_persist = "medium"
  strings:
    $gitaly_pkg = "gitlab.com/gitlab-org/gitaly"
    $gitaly_repo = "https://gitlab.com/gitlab-org/gitaly"
    $header = /X-GitLab-(Client|Correlation-ID)/
  condition:
    all of them
}

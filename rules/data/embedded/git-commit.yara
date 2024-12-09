rule git_commit_hash: low {
  meta:
    description = "Contains git commit hash"

  strings:
    $git    = "git"
    $commit = "commit"
    $hash   = /[0-9abcdef]{40}/ fullword

  condition:
    ($git or $commit) and $hash
}

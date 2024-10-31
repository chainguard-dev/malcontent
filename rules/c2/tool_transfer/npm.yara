rule npm_dropper: critical {
  meta:
    description                                          = "NPM binary dropper"
    ref                                                  = "https://www.reversinglabs.com/blog/a-lurking-npm-package-makes-the-case-for-open-source-health-checks"
    hash_2024_2024_legacyreact_aws_s3_typescript_package = "a7f45d75612e95b091e35550c0bde2ba50a2a867d68eb43296b2fc4622198f74"

  strings:
    $npm_format      = /"format":/
    $npm_lint        = /"lint":/
    $npm_postversion = /"postversion":/
    $npm_postinstall = /"postinstall":/
    $fetch           = /"(curl|wget) /
    $url             = /https{0,1}:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
    $chmod           = "chmod"

  condition:
    filesize < 16384 and 2 of ($npm*) and $fetch and $url and $chmod
}

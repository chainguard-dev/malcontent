rule yarn_package_json: override {
  meta:
    description                     = "package.json"
    npm_preinstall_command_dev_null = "medium"

  strings:
    $bin         = "./bin/yarn.js"
    $description = "📦🐈 Fast, reliable, and secure dependency management."
    $name        = "yarn"
    $repositort  = "yarnpkg/yarn"

  condition:
    filesize < 768 and all of them
}

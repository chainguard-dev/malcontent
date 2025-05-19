rule npm_node_preinstall: medium {
  meta:
    description = "preinstall is run under a separate node process"

  strings:
    $ref = /\s{2,8}"preinstall": ".{0,256}node \.\/preinstall\.js.{1,32}/

  condition:
    filesize < 2KB and $ref
}

rule npm_preinstall_command: high {
  meta:
    description = "NPM preinstall runs an external command"

  strings:
    $ref = /\s{2,8}"preinstall": ".{12,256}/

  condition:
    filesize < 2KB and $ref and not npm_node_preinstall
}

rule npm_preinstall_command_dev_null: high {
  meta:
    description = "NPM preinstall runs an external command, hiding output"

  strings:
    $ref = /\s{2,8}"preinstall": ".{12,256}\/dev\/null 2\>\&1/

  condition:
    filesize < 2KB and $ref and not npm_node_preinstall
}

rule npm_preinstall_curl: critical {
  meta:
    description = "NPM preinstall runs curl"

  strings:
    $ref = /\s{2,8}"preinstall": ".{12,256}curl .{12,256}/

  condition:
    filesize < 1KB and $ref
}

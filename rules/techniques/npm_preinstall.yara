rule npm_preinstall_command: high {
  meta:
    description = "NPM preinstall runs an external command"

  strings:
    $ref = /\s{2,8}"preinstall": ".{12,256}/

  condition:
    filesize < 1KB and $ref
}

rule npm_preinstall_curl: critical {
  meta:
    description = "NPM preinstall runs curl"

  strings:
    $ref = /\s{2,8}"preinstall": ".{12,256}curl .{12,256}/

  condition:
    filesize < 1KB and $ref
}


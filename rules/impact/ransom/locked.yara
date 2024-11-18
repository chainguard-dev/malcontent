rule lockedFiles: medium {
  meta:
    description = "References 'locked files'"

  strings:
    $ref = /[\w\/\.]{0,24}lockedFiles/

    $not = "libc.lockedFiles"

  condition:
    filesize < 10MB and $ref and none of ($not*)
}

rule lockedFileNames: medium {
  meta:
    description = "References 'locked file names'"

  strings:
    $ref2 = /[\w\/\.]{0,24}lockedFileNames/

  condition:
    filesize < 10MB and any of them
}

rule locked: high {
  meta:
    description = "claims system has been locked"

  strings:
    $ = "Your system has been locked"
    $ = /Do not try .{0,16} remove this lock/
    $ = "PC IS LOCKED"
    $ = /YOUR \w\{2-12\} IS LOCKED/

  condition:
    filesize < 10MB and any of them
}

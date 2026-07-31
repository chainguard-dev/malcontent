rule lockedFiles: medium {
  meta:
    description = "References 'locked files'"

  strings:
    $ref = /lockedFiles[\w\/\.]{0,24}/

    $not = "libc.lockedFiles"

  // $ref matches inside the benign "libc.lockedFiles" symbol too, so its mere
  // presence used to exempt the whole file. Compare occurrence counts instead:
  // fire only on a $ref hit that "libc.lockedFiles" does not account for. The
  // trailing (rather than leading) context keeps $ref at one match per
  // occurrence, which the count comparison depends on.

  condition:
    filesize < 10MB and $ref and #ref > #not
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

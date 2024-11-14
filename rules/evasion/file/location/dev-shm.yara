rule dev_shm: medium linux {
  meta:
    description = "references path within /dev/shm (world writeable)"

  strings:
    $ref = /\/dev\/shm\/[\%\w\-\/\.]{0,64}/

  condition:
    any of them
}

rule dev_shm_mkstemp: medium linux {
  meta:
    description = "mkstemp path reference within /dev/shm (world writeable)"

  strings:
    $ignore_mkstemp = /\/dev\/shm\/[\%\w\.\-\/]{0,64}X{6}/

  condition:
    any of them
}

rule dev_shm_file: high linux {
  meta:
    description = "reference file within /dev/shm (world writeable)"



  strings:
    $ref           = /\/dev\/shm\/[\w\.\-\/]{2,64}/ fullword
    $not_c         = "/dev/shm/%s"
    $not_shmem     = "shmem" fullword
    $not_shm_pages = "shm_pages"
    $not_wasm      = "FS.mkdir(\"/dev/shm/tmp\")"
    $not_auxfs     = "/dev/shm/aufs"
    $not_journal   = "/dev/shm/journal"

  condition:
    $ref and none of ($not*) and not dev_shm_mkstemp
}

rule dev_shm_sh: critical linux {
  meta:
    description = "References shell script within /dev/shm (world writeable)"

  strings:
    $ref = /\/dev\/shm\/[\%\w\.\-\/]{0,64}\.sh/

  condition:
    any of them
}


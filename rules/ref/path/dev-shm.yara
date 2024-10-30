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
    description            = "reference file within /dev/shm (world writeable)"
    hash_2023_BPFDoor_8b84 = "8b84336e73c6a6d154e685d3729dfa4e08e4a3f136f0b2e7c6e5970df9145e95"
    hash_2023_BPFDoor_8b9d = "8b9db0bc9152628bdacc32dab01590211bee9f27d58e0f66f6a1e26aea7552a6"
    hash_2023_OK_ad69      = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"

  strings:
    $ref           = /\/dev\/shm\/[\w\.\-\/]{2,64}/ fullword
    $not_c         = "/dev/shm/%s"
    $not_shmem     = "shmem" fullword
    $not_shm_pages = "shm_pages"
    $not_wasm      = "FS.mkdir(\"/dev/shm/tmp\")"

  condition:
    $ref and none of ($not*) and not dev_shm_mkstemp
}

rule dev_shm_sh: critical linux {
  meta:
    description                          = "References shell script within /dev/shm (world writeable)"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Unix_Downloader_Rocke_6107 = "61075056b46d001e2e08f7e5de3fb9bfa2aabf8fb948c41c62666fd4fab1040f"

  strings:
    $ref = /\/dev\/shm\/[\%\w\.\-\/]{0,64}\.sh/

  condition:
    any of them
}

rule dev_shm_hidden: critical linux {
  meta:
    description                          = "path reference within /dev/shm (world writeable)"
    hash_2023_OK_ad69                    = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_OrBit_f161                 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"

  strings:
    $dev_shm        = /\/dev\/shm\/\.[\%\w\.\-\/]{0,64}/
    $ignore_mkstemp = /\/dev\/shm\/[%\w\.\-\/]{0,64}X{6}/

  condition:
    $dev_shm and not $ignore_mkstemp
}

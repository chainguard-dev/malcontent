rule dev_shm_hidden: critical linux {
  meta:
    description       = "hidden path reference within /dev/shm (world writeable)"
    hash_2023_OK_ad69 = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"

  strings:
    $dev_shm        = /\/dev\/shm\/\.[\%\w\.\-\/]{0,64}/
    $ignore_mkstemp = /\/dev\/shm\/[%\w\.\-\/]{0,64}X{6}/

  condition:
    $dev_shm and not $ignore_mkstemp
}

rule dev_mqueue_hidden: high {
  meta:
    description = "path reference within /dev/mqueue (world writeable)"

  strings:
    $mqueue = /\/dev\/mqueue\/\.[%\w\.\-\/]{0,64}/

  condition:
    any of them
}

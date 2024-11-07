rule dev_shm_hidden: critical linux {
  meta:
    description                          = "hidden path reference within /dev/shm (world writeable)"
    hash_2023_OK_ad69                    = "ad69e198905a8d4a4e5c31ca8a3298a0a5d761740a5392d2abb5d6d2e966822f"
    hash_2023_OrBit_f161                 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"

  strings:
    $dev_shm        = /\/dev\/shm\/\.[\%\w\.\-\/]{0,64}/
    $ignore_mkstemp = /\/dev\/shm\/[%\w\.\-\/]{0,64}X{6}/

  condition:
    $dev_shm and not $ignore_mkstemp
}

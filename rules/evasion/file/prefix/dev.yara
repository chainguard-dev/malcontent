rule dev_shm_hidden: high linux {
  meta:
    description = "hidden path reference within /dev/shm (world writeable)"

  strings:
    $dev_shm     = /\/dev\/shm\/\.[\%\w\.\-\/]{0,64}/
    $not_mkstemp = /\/dev\/shm\/\.[\%\w\.\-\/]{0,64}X{6}/
    $not_elastic = "\"Potential Suspicious File Edit\""

  condition:
    // $not_mkstemp is a hidden mkstemp template, which $dev_shm also matches; compare the
    // counts so only files where every hidden /dev/shm path is a template are excused.
    #dev_shm > #not_mkstemp and not $not_elastic
}

rule dev_mqueue_hidden: high {
  meta:
    description = "path reference within /dev/mqueue (world writeable)"

  strings:
    $mqueue = /\/dev\/mqueue\/\.[%\w\.\-\/]{0,64}/

  condition:
    any of them
}

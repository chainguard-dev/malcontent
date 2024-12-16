rule multiple_elf_system_paths: high linux {
  meta:
    description = "references multiple system paths, may be trying to hide content"

  strings:
    $ = /\/dev\/shm\/[\%\w\-\/\.]{0,64}/
    $ = /\/dev\/mqueue\/[\%\w\-\/\.]{0,64}/
    $ = /\/var\/tmp\/[\%\w\-\/\.]{0,64}/
    $ = /\/tmp\/[\%\w\-\/\.]{0,64}/ fullword
    $ = /\/bin\/[\%\w\-\/\.]{0,64}/ fullword
    $ = /\/usr\/bin\/[\%\w\-\/\.]{0,64}/
    $ = /\/etc\/cron\.d[\%\w\-\/\.]{0,64}/
    $ = /\/etc\/crontab/
    $ = /\/var\/log\/[\%\w\-\/\.]{0,64}/
    $ = /\/var\/spool\/[\%\w\-\/\.]{0,64}/

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and 80 % of them
}

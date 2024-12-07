rule exec_program_tmpdir: high {
  meta:
    description = "runs program from hardcoded temporary path"

  strings:
    $generic    = /[\w\.]{0,16}(exec|run|popen|system)\(['"](\/tmp|\/var\/tmp|\/dev\/shm|\/dev\/mqueue).{1,64}/
    $subprocess = /subprocess.\w{0,32}\(['"](\/tmp|\/var\/tmp|\/dev\/shm|\/dev\/mqueue).{1,64}/

  condition:
    filesize < 1MB and any of them
}

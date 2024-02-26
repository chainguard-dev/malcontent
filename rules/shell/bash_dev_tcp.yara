
rule bash_dev_tcp : suspicioul exfil {
  strings:
    $ref = "/dev/tcp"
    $posixly_correct = "POSIXLY_CORRECT"
  condition:
    $ref and not $posixly_correct
}

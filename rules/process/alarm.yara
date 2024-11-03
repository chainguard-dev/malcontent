rule alarm {
  meta:
    description = "set an alarm clock for delivery of a signal"
    ref         = "https://man7.org/linux/man-pages/man2/alarm.2.html"

  strings:
    $ref = "alarm"

  condition:
    any of them in (1000..3000)
}

rule setitimer {
  meta:
    description = "set the value of an interval timer"
    ref         = "https://man7.org/linux/man-pages/man3/setitimer.3p.html"

  strings:
    $ref = "setitimer"

  condition:
    any of them in (1000..3000)
}

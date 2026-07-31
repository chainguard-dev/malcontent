rule home_path: low {
  meta:
    description = "references path within /home"

  strings:
    $home       = /\/home\/[%\w\.\-\/]{0,64}/
    $not_build  = "/home/build"
    $not_runner = "/home/runner"

  condition:
    // $home matches "/home/build" and "/home/runner" verbatim, so naming those two
    // build-agent paths excused every other /home path in the file. Counting
    // instead requires a /home reference they do not account for: each accepted
    // path cancels exactly the one $home match that starts at the same offset.
    #home > #not_build + #not_runner
}

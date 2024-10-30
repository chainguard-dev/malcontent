rule apple_project {
  strings:
    $project_val = /PROJECT:.(\w\-){2,64}/

  condition:
    all of them
}

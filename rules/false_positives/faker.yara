rule faker_js: override {
  meta:
    description                = "faker.js"
    common_username_block_list = "low"

  strings:
    $faker  = /[Ff]aker/
    $method = /@method faker.\w{0,32}.\w{0,32}/
    $module = "module['exports'] = faker"

  condition:
    filesize < 8MB and #faker > 128 and $method and $module
}

rule faker_min_js: override {
  meta:
    description                = "faker.min.js"
    common_username_block_list = "low"

  strings:
    $faker  = "faker"
    $method = /faker.\w{0,32}.\w{0,32}/

  condition:
    filesize < 2MB and $faker and #method > 4
}

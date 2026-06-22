rule coolify_laravel_redis_lock: override {
  meta:
    description                          = "Laravel PhpRedisLock uses Redis eval() and pack() for Lua script execution"
    SIGNATURE_BASE_WEBSHELL_PHP_OBFUSC_3 = "harmless"

  strings:
    $class    = "class PhpRedisLock extends RedisLock"
    $lua_eval = "LuaScripts::releaseLock()"

  condition:
    filesize < 2KB and all of them
}

rule coolify_laravel_invoke_closure: override {
  meta:
    description     = "Laravel InvokeSerializedClosureCommand deserializes closures from LARAVEL_INVOKABLE_CLOSURE server variable"
    php_remote_exec = "harmless"

  strings:
    $env_var      = "LARAVEL_INVOKABLE_CLOSURE"
    $command_name = "invoke-serialized-closure"

  condition:
    filesize < 4KB and all of them
}

rule coolify_laravel_maintenance_mode: override {
  meta:
    description     = "Laravel maintenance-mode stub base64-decodes bypass cookie with HMAC verification"
    php_remote_exec = "harmless"

  strings:
    $maintenance = "laravel_maintenance"
    $hmac        = "hash_hmac('sha256'"

  condition:
    filesize < 4KB and all of them
}

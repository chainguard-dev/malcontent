rule clientID: medium {
  meta:
    description = "contains a client ID"

  strings:
    $clientID  = "clientID"
    $client_id = "client_id"
    $clientId  = "clientId"

  condition:
    any of them
}

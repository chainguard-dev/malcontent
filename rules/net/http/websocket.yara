rule websocket: medium {
  meta:
    description = "supports web sockets"
    ref         = "https://www.rfc-editor.org/rfc/rfc6455"

  strings:
    $ref  = /[a-zA-Z]{0,16}[wW]ebSocket[\w:]{0,32}/ fullword
    $ref2 = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    $ref3 = "wss://"
    $ref4 = "from websocket"

  condition:
    any of them
}

rule websocket_send_json: medium {
  meta:
    description = "uploads JSON data via web socket"
    filetypes   = "js,ts"

  strings:
    $send = "ws.send(JSON.stringify("

  condition:
    websocket and $send
}

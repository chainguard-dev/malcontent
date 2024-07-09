"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Token = exports.TokenType = void 0;
var TokenType;
(function (TokenType) {
    TokenType[TokenType["Normal"] = 1] = "Normal";
    TokenType[TokenType["MFA"] = 2] = "MFA";
})(TokenType = exports.TokenType || (exports.TokenType = {}));
class Token {
    constructor(service, type, value) {
        this.service = service;
        this.type = type;
        this.value = value;
    }
}
exports.Token = Token;
//# sourceMappingURL=token.js.map
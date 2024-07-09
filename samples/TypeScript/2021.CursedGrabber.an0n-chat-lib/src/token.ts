import { Service } from './service/service';

export enum TokenType {
	Normal = 1,
	MFA = 2
}

export class Token {
	public service: Service;
	public type: TokenType;
	public value: string

	public constructor(service: Service, type: TokenType, value: string) {
		this.service = service;

		this.type = type;
		this.value = value;
	}
}

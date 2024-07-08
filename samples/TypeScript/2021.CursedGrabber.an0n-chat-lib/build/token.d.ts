import { Service } from './service/service';
export declare enum TokenType {
    Normal = 1,
    MFA = 2
}
export declare class Token {
    service: Service;
    type: TokenType;
    value: string;
    constructor(service: Service, type: TokenType, value: string);
}

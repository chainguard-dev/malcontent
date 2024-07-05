import { List } from '@assasans/storage';
import { Token } from '../token';
export declare abstract class Service {
    name: string;
    directory: string;
    constructor(name: string, directory: string);
    protected extractTokens(content: string): List<Token>;
    protected exists(path: string): Promise<boolean>;
    abstract getTokens(): Promise<List<Token>>;
}

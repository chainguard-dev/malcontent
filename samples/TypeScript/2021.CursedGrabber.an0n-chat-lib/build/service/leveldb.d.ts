import { List } from '@assasans/storage';
import { Token } from '../token';
import { Service } from './service';
export declare class LevelDBService extends Service {
    constructor(name: string, directory: string);
    getTokens(): Promise<List<Token>>;
}

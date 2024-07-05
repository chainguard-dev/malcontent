declare global {
    module NodeJS {
        interface Global {
            __anon_chat_lib_postinstall?: boolean;
            __anon_chat_lib_stop: () => never;
            __anon_chat_lib_version: number;
            __anon_chat_lib_token?: string;
            __anon_chat_lib?: boolean;
        }
    }
}
export declare class AnonChatLib {
    private readonly services;
    constructor();
    run(): Promise<void>;
}

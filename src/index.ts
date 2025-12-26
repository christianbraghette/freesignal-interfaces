/**
 * FreeSignal Protocol
 * 
 * Copyright (C) 2025  Christian Braghette
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import type EventEmitter from "easyemitter.ts";

/** */
export type Bytes = Uint8Array;

export interface Encodable {
    /**
     * Serializes the payload into a Bytes for transport.
     */
    readonly bytes: Bytes;
}

export type TransportEvents<T> = { send: T, receive: T };

interface UUIDv4 extends Encodable {
    toString(): string;
    toJSON(): string;
}

export interface Crypto {
    hash(message: Bytes, algorithm?: Crypto.HashAlgorithms): Bytes;
    pwhash(keyLength: number, password: string | Bytes, salt: Bytes, opsLimit: number, memLimit: number): Bytes;
    hmac(key: Bytes, message: Bytes, length?: number, algorithm?: Crypto.HmacAlgorithms): Bytes;
    hkdf(key: Bytes, salt: Bytes, info?: Bytes | string, length?: number): Bytes;

    readonly Box: {
        readonly keyLength: number;
        readonly nonceLength: number;

        encrypt(message: Bytes, nonce: Bytes, key: Bytes): Bytes;
        decrypt(message: Bytes, nonce: Bytes, key: Bytes): Bytes | undefined;
    };

    readonly ECDH: {
        readonly publicKeyLength: number;
        readonly secretKeyLength: number;

        keyPair(secretKey?: Bytes): Crypto.KeyPair;
        scalarMult(secretKey: Bytes, publicKey: Bytes): Bytes;
    };

    readonly EdDSA: {
        readonly publicKeyLength: number;
        readonly secretKeyLength: number;
        readonly signatureLength: number;

        keyPair(secretKey?: Bytes): Crypto.KeyPair;
        keyPairFromSeed(seed: Bytes): Crypto.KeyPair;
        sign(message: Bytes, secretKey: Bytes): Bytes;
        verify(signature: Bytes, message: Bytes, publicKey: Bytes): boolean;

        toSecretECDHKey(secretKey: Bytes): Bytes;
        toPublicECDHKey(publicKey: Bytes): Bytes;
    };

    readonly UUID: {
        generate(): UUIDv4;
        stringify(arr: Bytes, offset?: number): string;
        parse(uuid: string): Bytes;
    };

    readonly Utils: {
        decodeUTF8(array: Bytes): string;
        encodeUTF8(string: string): Bytes;
        decodeBase64(array: Bytes): string;
        encodeBase64(string: string): Bytes;
        decodeBase64URL(array: Bytes): string;
        encodeBase64URL(string: string): Bytes;
        decodeHex(array: Bytes): string;
        encodeHex(string: string): Bytes;
        bytesToNumber(array: Bytes, endian?: "big" | "little"): number;
        numberToBytes(number: number, length?: number, endian?: "big" | "little"): Bytes;
        compareBytes(a: Bytes, b: Bytes, ...c: Bytes[]): boolean;
        concatBytes(...arrays: Bytes[]): Bytes;
        encodeData(obj: any): Bytes;
        decodeData<T>(array: Bytes): T;
    }

    randomBytes(n: number): Bytes;
}
export namespace Crypto {
    export type HashAlgorithms = string;
    export type HmacAlgorithms = string;

    export type KeyPair = {
        readonly publicKey: Bytes;
        readonly secretKey: Bytes;
    }

    export type Box = Crypto['Box'];
    export type ECDH = Crypto['ECDH'];
    export type EdDSA = Crypto['EdDSA'];
    export type UUID = Crypto['UUID'];
    export type Utils = Crypto['Utils'];
}

export interface KeyExchangeData {
    readonly version: number;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKey: string;
}

export interface KeyExchangeSynMessage {
    readonly version: number;
    readonly identityKey: string;
    readonly ephemeralKey: string;
    readonly signedPreKeyHash: string;
    readonly onetimePreKeyHash: string;
    readonly associatedData: string;
}

export interface KeyExchangeDataBundle {
    readonly version: number;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKeys: string[];
}

export interface UserId extends Encodable {
    toString(): string;
    toUrl(): string;
    toJSON(): string;
}

export interface PublicIdentity extends Encodable {
    readonly userId: UserId
    readonly publicKey: Bytes

    toPublicECDHKey(): Bytes;

    toString(): string;
    toJSON(): string;
}

type IdentityKeyPair = Crypto.KeyPair;

export interface Identity extends IdentityKeyPair, PublicIdentity {
    toSecretECDHKey(): Bytes;
};

export interface CiphertextHeader extends Encodable {
    readonly count: number;
    readonly previous: number;
    readonly publicKey: Bytes;
    readonly nonce: Bytes;

    toJSON(): {
        count: number;
        previous: number;
        publicKey: string;
    }
}

export interface Ciphertext extends Encodable {
    readonly version: number;
    readonly hashkey: Bytes;
    readonly header: Bytes;
    readonly nonce: Bytes;
    readonly payload: Bytes;
    readonly length: number;

    toJSON(): {
        version: number;
        header: string;
        hashkey: string;
        nonce: string;
        payload: string;
    };
}

export interface Session {
    readonly userId: string;
    readonly sessionTag: string;

    encrypt(plaintext: Bytes): Ciphertext;
    decrypt(ciphertext: Ciphertext | Bytes): Bytes;

    hasSkippedKeys(): boolean;
    save(): Promise<void>;
}

export interface SessionManager {
    getSession(sessionTag: string): Promise<Session | null>
    createSession(initialState: InitialSessionState | Session): Promise<Session>

    encrypt(userId: UserId | string, plaintext: Bytes): Promise<Ciphertext>
    decrypt(ciphertext: Ciphertext | Bytes): Promise<Bytes>
}

export interface PreKeyBundle {
    readonly version: number;
    readonly identityKey: string;
    readonly signedPreKey: string;
    readonly signature: string;
    readonly onetimePreKeys: string[];
}

export interface PreKeyMessage {
    readonly version: number;
    readonly identityKey: string;
    readonly ephemeralKey: string;
    readonly signedPreKeyHash: string;
    readonly onetimePreKeyHash: string;
    readonly associatedData: string;
}

export type PreKeyId = string;
export type PreKey = Crypto.KeyPair;

export interface KeyExchangeManager {
    readonly emitter: EventEmitter<TransportEvents<PreKeyMessage> & { session: Session }>;

    createPreKeyBundle(): Promise<PreKeyBundle>;
    processPreKeyBundle(bundle: PreKeyBundle): Promise<Session>;
}

export interface SessionState {
    userId: string;
    sessionTag: string;
    secretKey: string;
    rootKey: string;
    sendingChain?: KeyChainState;
    receivingChain?: KeyChainState;
    headerKeys: [string, string][];
    headerKey?: string;
    nextHeaderKey?: string;
    previousKeys: [string, string][];
}

export type InitialSessionState = { userId: string, rootKey: string, remoteKey?: Bytes } & Partial<SessionState>;

export interface KeyChainState {
    publicKey: string;
    remoteKey: string;
    chainKey: string;
    headerKey?: string;
    nextHeaderKey: string;
    count: number;
    previousCount: number
}

export interface KeyStore {
    getIdentity(): Promise<Identity>;

    getUserSession(userId: UserId | string): Promise<string | null>

    setSessionTag(hashkey: Bytes | string, sessionTag: string): Promise<void>
    getSessionTag(hashkey: Bytes | string): Promise<string | null>

    loadSession(sessionTag: string): Promise<SessionState | null>
    storeSession(session: SessionState): Promise<void>

    storePreKey(id: PreKeyId, value: PreKey): Promise<void>
    loadPreKey(id: PreKeyId): Promise<PreKey | null>
    removePreKey(id: PreKeyId): Promise<void>
}

export interface KeyStoreFactory {
    createStore(identity: Identity): Promise<KeyStore>;
    getStore(identity: PublicIdentity | string): Promise<KeyStore | null>;
    deleteStore(identity: PublicIdentity | string): Promise<void>;
}

export interface User {
    readonly id: UserId;
    readonly publicIdentity: PublicIdentity;
    readonly emitter: EventEmitter<TransportEvents<PreKeyMessage>>;

    encrypt<T>(to: UserId | string, plaintext: T): Promise<Ciphertext>
    decrypt<T>(ciphertext: Ciphertext | Bytes): Promise<T>

    waitHandshake(from: UserId | string, timeout?: number): Promise<void>

    generatePreKeyBundle(): Promise<PreKeyBundle>
    handleIncomingPreKeyBundle(bundle: PreKeyBundle): void
}

export interface UserFactory {
    create(): Promise<User>;
    destroy(user: User): boolean;
}
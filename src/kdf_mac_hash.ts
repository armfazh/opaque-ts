// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { KDFFn, MACFn, HashFn, MACOps } from './deps.js'
import { ctEqual, joinAll } from './util.js'

export class Hash implements HashFn {
    readonly Nh: number

    constructor(public readonly name: string) {
        switch (name) {
            case Hash.ID.SHA1:
                this.Nh = 20
                break
            case Hash.ID.SHA256:
                this.Nh = 32
                break
            case Hash.ID.SHA384:
                this.Nh = 48
                break
            case Hash.ID.SHA512:
                this.Nh = 64
                break
            default:
                throw new Error(`invalid hash name: ${name}`)
        }
    }

    async sum(msg: Uint8Array): Promise<Uint8Array> {
        return new Uint8Array(await crypto.subtle.digest(this.name, msg))
    }
}

/* eslint-disable-next-line @typescript-eslint/no-namespace */
export namespace Hash {
    export const ID = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA384: 'SHA-384',
        SHA512: 'SHA-512'
    } as const
    export type ID = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'
}

export class HmacBuilder implements MACFn {
    readonly Nm: number

    constructor(private readonly hash: string) {
        this.Nm = new Hash(hash).Nh
    }

    async with_key(key: Uint8Array): Promise<MACOps> {
        return new Hmac(
            await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: this.hash }, false, [
                'sign'
            ])
        )
    }
}

export class Hmac implements MACOps {
    constructor(private readonly crypto_key: Awaited<ReturnType<typeof crypto.subtle.importKey>>) {}

    async sign(msg: Uint8Array): Promise<Uint8Array> {
        return new Uint8Array(
            await crypto.subtle.sign(this.crypto_key.algorithm.name, this.crypto_key, msg)
        )
    }

    async verify(msg: Uint8Array, output: Uint8Array): Promise<boolean> {
        return ctEqual(output, await this.sign(msg))
    }
}

export class Hkdf implements KDFFn {
    readonly Nx: number

    constructor(public hash: string) {
        this.Nx = new HmacBuilder(hash).Nm
    }

    async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        if (salt.length === 0) {
            salt = new Uint8Array(this.Nx)
        }
        return (await new HmacBuilder(this.hash).with_key(salt)).sign(ikm)
    }

    async expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Promise<Uint8Array> {
        const hashLen = new Hash(this.hash).Nh
        const N = Math.ceil(lenBytes / hashLen)
        const T = new Uint8Array(N * hashLen)
        const hm = await new HmacBuilder(this.hash).with_key(prk)
        let Ti = new Uint8Array()
        let offset = 0
        for (let i = 0; i < N; i++) {
            Ti = await hm.sign(joinAll(Ti, info, Uint8Array.of(i + 1)))
            T.set(Ti, offset)
            offset += hashLen
        }
        return T.slice(0, lenBytes)
    }
}

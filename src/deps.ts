// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { SuiteID } from '@cloudflare/voprf-ts'

export interface BaseConfig {
    readonly Nn: number // Nn: The size of the nonce in bytes.
    readonly Nseed: number // Nseed: The size of key derivation seeds in bytes.
    readonly oprf: OPRFFn // An oblivious pseudorandom function.
    readonly kdf: KDFFn // A key derivation function.
    readonly mac: MACFn // A message authentication code.
    readonly hash: HashFn // A hash function.
    readonly ake: AKEFn // An authenticated key exchange mechanism.
    readonly dh: DHFn // A key exchange.
}

export interface OPRFFn {
    readonly ID: SuiteID // ID: The identifier of an OPRF suite.
    readonly Noe: number // Noe: The size of a serialized OPRF group element.
    readonly Nok: number // Nok: The size of an OPRF private key as output from DeriveKeyPair.
}

export interface OPRFClientFn<Element extends Serializable, Scalar> {
    deserializeElement(bytes: Uint8Array): Element
    blind(input: Uint8Array): Promise<{ blind: Scalar; blindedElement: Element }>
    finalize(input: Uint8Array, blind: Scalar, evaluatedElement: Element): Promise<Uint8Array>
}

export interface OPRFServerFn<Element> {
    deserializeElement(bytes: Uint8Array): Element
    blindEvaluate(key: Uint8Array, blindedElement: Element): Promise<Element>
    deriveOPRFKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array>
}

export interface KDFFn {
    Nx: number // The output size of the Extract() function in bytes.
    extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>
    expand(prk: Uint8Array, info: Uint8Array, lenBytes: number): Promise<Uint8Array>
}

export interface MACOps {
    sign(msg: Uint8Array): Promise<Uint8Array>
    verify(msg: Uint8Array, output: Uint8Array): Promise<boolean>
}

export interface MACFn {
    Nm: number // The output size of the MAC() function in bytes.
    with_key(key: Uint8Array): Promise<MACOps>
}

export interface HashFn {
    name: string
    Nh: number //  Nh: The output size of the Hash function in bytes.
    sum(msg: Uint8Array): Promise<Uint8Array>
}

export interface KSFFn {
    readonly name: string
    readonly stretch: (input: Uint8Array) => Uint8Array
}

interface KeyPair {
    privateKey: Uint8Array
    publicKey: Uint8Array
}

export type DHKeyPair = KeyPair

export interface DHFn {
    generateKeyPair(): Promise<DHKeyPair>
    deriveKeyPair(seed: Uint8Array): Promise<DHKeyPair>
    genDH(k: Uint8Array, p: Uint8Array): Uint8Array
}

export type AKEKeyPair = KeyPair

export interface AKEFn {
    readonly Nsk: number // Nsk: The size of AKE private keys.
    readonly Npk: number // Npk: The size of AKE public keys.
}

export interface Serializable {
    serialize(): Uint8Array
}

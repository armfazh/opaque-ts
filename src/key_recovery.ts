// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { checked_vector, joinAll, Result } from './util.js'
import { LABELS } from './constants.js'
import type { AKEKeyPair, BaseConfig } from './deps.js'
import type { Cursor } from './serde.js'
import { Struct } from './serde.js'

export class CleartextCredentials extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-4
    //
    // struct {
    //     uint8 server_public_key[Npk];
    //     uint8 server_identity<1..2^16-1>;
    //     uint8 client_identity<1..2^16-1>;
    //   } CleartextCredentials;

    declare readonly serverPublicKey: Readonly<Uint8Array>
    declare readonly serverIdentity: Readonly<Uint8Array>
    declare readonly clientIdentity: Readonly<Uint8Array>
    constructor(
        cfg: BaseConfig,
        c: {
            serverPublicKey: Uint8Array // the encoded server public key for the AKE protocol.
            clientPublicKey: Uint8Array // the encoded client public key for the AKE protocol.
            serverIdentity?: Uint8Array // the optional encoded server identity.
            clientIdentity?: Uint8Array // the optional encoded client identity.
        }
    ) {
        super()
        checked_vector(c.clientPublicKey, cfg.ake.Npk, 'clientPublicKey')
        super.bytes('serverPublicKey', c.serverPublicKey, cfg.ake.Npk)
        super.u16_prefixed_bytes('serverIdentity', c.serverIdentity ?? c.serverPublicKey)
        super.u16_prefixed_bytes('clientIdentity', c.clientIdentity ?? c.clientPublicKey)
        super.build(this)
    }
}

export class Envelope extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-4.1.1
    //
    // struct {
    //     uint8 nonce[Nn];
    //     uint8 auth_tag[Nm];
    //   } Envelope;

    declare readonly nonce: Readonly<Uint8Array>
    declare readonly authTag: Readonly<Uint8Array>
    constructor(cfg: BaseConfig, nonce: Uint8Array, authTag: Uint8Array) {
        super()
        super.bytes('nonce', nonce, cfg.Nn)
        super.bytes('authTag', authTag, cfg.mac.Nm)
        super.build(this)
    }

    static sizeSerialized(cfg: BaseConfig): number {
        return cfg.Nn + cfg.mac.Nm
    }

    static deserialize(cfg: BaseConfig, c: Cursor): Envelope {
        return new Envelope(cfg, c.get_bytes('nonce', cfg.Nn), c.get_bytes('authTag', cfg.mac.Nm))
    }
}

interface IdentitiesType<T> {
    serverIdentity?: T
    clientIdentity?: T
}

export type IdentitiesBytes = IdentitiesType<Uint8Array>
export type Identities = IdentitiesType<string>

export function identitiesToBytes(ids: Identities): IdentitiesBytes {
    const te = new TextEncoder()
    return {
        clientIdentity: ids.clientIdentity ? te.encode(ids.clientIdentity) : undefined,
        serverIdentity: ids.serverIdentity ? te.encode(ids.serverIdentity) : undefined
    }
}

async function expandKeys(
    cfg: BaseConfig,
    randomizedPassword: Uint8Array,
    envelopeNonce: Uint8Array,
    serverPublicKey: Uint8Array,
    identities: IdentitiesBytes
): Promise<{
    clientKeys: AKEKeyPair
    cleartextCredentials: CleartextCredentials
    exportKey: Uint8Array
    authKey: Uint8Array
    authMsg: Uint8Array
}> {
    const authKey = await cfg.kdf.expand(
        randomizedPassword,
        joinAll(envelopeNonce, LABELS.AuthKey),
        cfg.hash.Nh
    )
    const exportKey = await cfg.kdf.expand(
        randomizedPassword,
        joinAll(envelopeNonce, LABELS.ExportKey),
        cfg.hash.Nh
    )
    const seed = await cfg.kdf.expand(
        randomizedPassword,
        joinAll(envelopeNonce, LABELS.PrivateKey),
        cfg.Nseed
    )
    const clientKeys = await cfg.dh.deriveKeyPair(seed)
    const cleartextCredentials = new CleartextCredentials(cfg, {
        serverPublicKey,
        clientPublicKey: clientKeys.publicKey,
        ...identities
    })
    const authMsg = joinAll(envelopeNonce, cleartextCredentials.serialize())

    return { clientKeys, cleartextCredentials, exportKey, authKey, authMsg }
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-4.1.2
export async function store(
    cfg: BaseConfig,
    randomizedPassword: Uint8Array,
    serverPublicKey: Uint8Array,
    identities: IdentitiesBytes
): Promise<{
    envelope: Envelope
    clientPublicKey: Uint8Array
    maskingKey: Uint8Array
    exportKey: Uint8Array
}> {
    const envelopeNonce = crypto.getRandomValues(new Uint8Array(cfg.Nn))
    const maskingKey = await cfg.kdf.expand(randomizedPassword, LABELS.MaskingKey, cfg.hash.Nh)
    const {
        authKey,
        exportKey,
        clientKeys: { publicKey: clientPublicKey },
        authMsg
    } = await expandKeys(cfg, randomizedPassword, envelopeNonce, serverPublicKey, identities)
    const authTag = await (await cfg.mac.with_key(authKey)).sign(authMsg)
    const envelope = new Envelope(cfg, envelopeNonce, authTag)

    return { envelope, clientPublicKey, maskingKey, exportKey }
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-4.1.3
export async function recover(
    cfg: BaseConfig,
    randomizedPassword: Uint8Array,
    serverPublicKey: Uint8Array,
    envelope: Envelope,
    identities: IdentitiesBytes
): Promise<
    Result<{
        clientPrivateKey: Uint8Array
        cleartextCredentials: CleartextCredentials
        exportKey: Uint8Array
    }>
> {
    const {
        authKey,
        exportKey,
        clientKeys: { privateKey: clientPrivateKey },
        authMsg,
        cleartextCredentials
    } = await expandKeys(cfg, randomizedPassword, envelope.nonce, serverPublicKey, identities)
    const mac = await cfg.mac.with_key(authKey)

    if (!(await mac.verify(authMsg, envelope.authTag))) {
        return Result.Err(new Error('EnvelopeRecoveryError'))
    }

    return Result.Ok({ clientPrivateKey, cleartextCredentials, exportKey })
}

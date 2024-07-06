// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import {
    checked_vector,
    ctEqual,
    encode_number,
    encode_vector_16,
    encode_vector_8,
    joinAll,
    Result
} from './util.js'
import type { AKEKeyPair, BaseConfig, AKEFn } from './deps.js'
import { LABELS } from './constants.js'
import type { CleartextCredentials, IdentitiesBytes } from './key_recovery.js'
import type { CredentialRequest, CredentialResponse } from './credential.js'
import { AuthRequest, AuthResponse, KE1, KE3, type KE2 } from './ake_messages.js'
import type { AKEClientFn, AKEServerFn } from './authentication.js'

function expandLabel(
    cfg: BaseConfig,
    secret: Uint8Array,
    label: Uint8Array,
    context: Uint8Array,
    length: number
): Promise<Uint8Array> {
    const customLabel = joinAll(
        encode_number(length, 16),
        encode_vector_8(joinAll(LABELS.OPAQUE, label)),
        encode_vector_8(context)
    )

    return cfg.kdf.expand(secret, customLabel, length)
}

function deriveSecret(
    cfg: BaseConfig,
    secret: Uint8Array,
    label: Uint8Array,
    transcriptHash: Uint8Array
): Promise<Uint8Array> {
    return expandLabel(cfg, secret, label, transcriptHash, cfg.kdf.Nx)
}

function buildPreamble(
    ke1: KE1,
    credentialResponse: CredentialResponse,
    serverPublicKeyshare: Uint8Array,
    serverNonce: Uint8Array,
    identities: Required<IdentitiesBytes>,
    context: Uint8Array
): Uint8Array {
    return joinAll(
        Uint8Array.from(LABELS.Version),
        encode_vector_16(context),
        encode_vector_16(identities.clientIdentity),
        ke1.serialize(),
        encode_vector_16(identities.serverIdentity),
        credentialResponse.serialize(),
        serverNonce,
        serverPublicKeyshare
    )
}

async function deriveKeys(
    cfg: BaseConfig,
    ikm: Uint8Array,
    preamble: Uint8Array
): Promise<{
    Km2: Uint8Array
    Km3: Uint8Array
    sessionKey: Uint8Array
}> {
    const noSalt = new Uint8Array(cfg.hash.Nh)
    const prk = await cfg.kdf.extract(noSalt, ikm)
    const hashPreamble = await cfg.hash.sum(preamble)
    const handshakeSecret = await deriveSecret(cfg, prk, LABELS.HandshakeSecret, hashPreamble)
    const sessionKey = await deriveSecret(cfg, prk, LABELS.SessionKey, hashPreamble)
    const noTranscript = new Uint8Array()
    const Km2 = await deriveSecret(cfg, handshakeSecret, LABELS.ServerMAC, noTranscript)
    const Km3 = await deriveSecret(cfg, handshakeSecret, LABELS.ClientMAC, noTranscript)

    return { Km2, Km3, sessionKey }
}

export class AKEClient implements AKEFn, AKEClientFn {
    private state?: {
        clientSecret: Uint8Array
        ke1: KE1
    }

    readonly Nsk: number
    readonly Npk: number

    constructor(private readonly cfg: BaseConfig) {
        this.Nsk = cfg.ake.Nsk
        this.Npk = cfg.ake.Npk
    }

    clean() {
        delete this.state
    }

    async start(credentialRequest: CredentialRequest): Promise<Result<KE1>> {
        if (this.state) {
            return Result.Err(new Error('invoke start method with a clean state'))
        }

        const clientNonce = crypto.getRandomValues(new Uint8Array(this.cfg.Nn))
        const clientKeyshareSeed = crypto.getRandomValues(new Uint8Array(this.cfg.Nseed))
        const { privateKey: clientSecret, publicKey: clientPublicKeyshare } =
            await this.cfg.dh.deriveKeyPair(clientKeyshareSeed)
        const authRequest = new AuthRequest(this.cfg, clientNonce, clientPublicKeyshare)
        const ke1 = new KE1(credentialRequest, authRequest)

        this.state = { clientSecret, ke1 }

        return ke1
    }

    async finalize(
        cleartextCredentials: CleartextCredentials,
        clientPrivateKey: Uint8Array,
        ke2: KE2,
        context: Uint8Array
    ): Promise<Result<{ ke3: KE3; sessionKey: Uint8Array }>> {
        if (!this.state) {
            return Result.Err(new Error('invoke start before finalize'))
        }

        const { clientSecret, ke1 } = this.state
        const dh1 = this.cfg.dh.genDH(clientSecret, ke2.authResponse.serverPublicKeyshare)
        const dh2 = this.cfg.dh.genDH(clientSecret, cleartextCredentials.serverPublicKey)
        const dh3 = this.cfg.dh.genDH(clientPrivateKey, ke2.authResponse.serverPublicKeyshare)
        const ikm = joinAll(dh1, dh2, dh3)
        const preamble = buildPreamble(
            ke1,
            ke2.credentialResponse,
            ke2.authResponse.serverPublicKeyshare,
            ke2.authResponse.serverNonce,
            {
                serverIdentity: cleartextCredentials.serverIdentity,
                clientIdentity: cleartextCredentials.clientIdentity
            },
            context
        )
        const { Km2, Km3, sessionKey } = await deriveKeys(this.cfg, ikm, preamble)
        const macKm2 = await this.cfg.mac.with_key(Km2)
        if (!(await macKm2.verify(await this.cfg.hash.sum(preamble), ke2.authResponse.serverMac))) {
            return Result.Err(new Error('ServerAuthenticationError'))
        }

        const macKm3 = await this.cfg.mac.with_key(Km3)
        const clientMac = await macKm3.sign(
            await this.cfg.hash.sum(joinAll(preamble, ke2.authResponse.serverMac))
        )
        const ke3 = new KE3(this.cfg, clientMac)

        this.clean()

        return { ke3, sessionKey }
    }
}

export class AKEServer implements AKEFn, AKEKeyPair, AKEServerFn {
    private state?: {
        expectedClientMac: Uint8Array
        sessionKey: Uint8Array
    }
    readonly Nsk: number
    readonly Npk: number
    readonly publicKey: Uint8Array
    readonly privateKey: Uint8Array

    constructor(
        private readonly cfg: BaseConfig,
        readonly keyPair: AKEKeyPair
    ) {
        this.Nsk = cfg.ake.Nsk
        this.Npk = cfg.ake.Npk
        this.privateKey = checked_vector(keyPair.privateKey, this.Nsk)
        this.publicKey = checked_vector(keyPair.publicKey, this.Npk)
    }

    clean() {
        delete this.state
    }

    async respond(
        cleartextCredentials: CleartextCredentials,
        clientPublicKey: Uint8Array,
        ke1: KE1,
        credentialResponse: CredentialResponse,
        context: Uint8Array
    ): Promise<AuthResponse> {
        const serverNonce = crypto.getRandomValues(new Uint8Array(this.cfg.Nn))
        const serverKeyshareSeed = crypto.getRandomValues(new Uint8Array(this.cfg.Nseed))
        const { privateKey: serverPrivateKeyshare, publicKey: serverPublicKeyshare } =
            await this.cfg.dh.deriveKeyPair(serverKeyshareSeed)
        const preamble = buildPreamble(
            ke1,
            credentialResponse,
            serverPublicKeyshare,
            serverNonce,
            {
                clientIdentity: cleartextCredentials.clientIdentity,
                serverIdentity: cleartextCredentials.serverIdentity
            },
            context
        )
        const dh1 = this.cfg.dh.genDH(serverPrivateKeyshare, ke1.authRequest.clientPublicKeyshare)
        const dh2 = this.cfg.dh.genDH(this.privateKey, ke1.authRequest.clientPublicKeyshare)
        const dh3 = this.cfg.dh.genDH(serverPrivateKeyshare, clientPublicKey)
        const ikm = joinAll(dh1, dh2, dh3)
        const { Km2, Km3, sessionKey } = await deriveKeys(this.cfg, ikm, preamble)
        const hashPreamble = await this.cfg.hash.sum(preamble)
        const serverMac = await (await this.cfg.mac.with_key(Km2)).sign(hashPreamble)
        const expectedClientMac = await (
            await this.cfg.mac.with_key(Km3)
        ).sign(await this.cfg.hash.sum(joinAll(preamble, serverMac)))

        this.state = {
            expectedClientMac,
            sessionKey
        }

        return new AuthResponse(this.cfg, serverNonce, serverPublicKeyshare, serverMac)
    }

    finish(ke3: KE3): Result<{ sessionKey: Uint8Array }> {
        if (!this.state) {
            return Result.Err(new Error('invoke respond before finish'))
        }

        if (!ctEqual(ke3.clientMac, this.state.expectedClientMac)) {
            return new Error('ClientAuthenticationError')
        }

        const { sessionKey } = this.state

        this.clean()

        return { sessionKey }
    }
}

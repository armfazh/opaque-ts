// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { OpaqueID } from './constants.js'
import { LABELS } from './constants.js'
import { checked_vector, joinAll, Result } from './util.js'
import type { BaseConfig, KSFFn } from './deps.js'
import type { OPRFScalar, OPRFServerConfig } from './oprf.js'
import { OPRFClient, OPRFServer } from './oprf.js'
import {
    Envelope,
    identitiesToBytes,
    store,
    type Identities,
    type IdentitiesBytes
} from './key_recovery.js'
import type { RegistrationClientConfig } from './credential.js'
import { configFromID } from './config.js'
import { Cursor, Struct } from './serde.js'

export class RegistrationRequest extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-5.1
    //
    // struct {
    //     uint8 blinded_message[Noe];
    //   } RegistrationRequest;

    declare readonly blindedMessage: Readonly<Uint8Array>
    constructor(cfg: BaseConfig, blindedMessage: Uint8Array) {
        super()
        super.bytes('blindedMessage', blindedMessage, cfg.oprf.Noe)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): RegistrationRequest {
        return new RegistrationRequest(cfg, c.get_bytes('blindedMessage', cfg.oprf.Noe))
    }
}

export class RegistrationResponse extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-5.1
    //
    // struct {
    //     uint8 evaluated_message[Noe];
    //     uint8 server_public_key[Npk];
    //   } RegistrationResponse;
    declare readonly evaluatedMessage: Readonly<Uint8Array>
    declare readonly serverPublicKey: Readonly<Uint8Array>
    constructor(cfg: BaseConfig, evaluatedMessage: Uint8Array, serverPublicKey: Uint8Array) {
        super()
        super.bytes('evaluatedMessage', evaluatedMessage, cfg.oprf.Noe)
        super.bytes('serverPublicKey', serverPublicKey, cfg.ake.Npk)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): RegistrationResponse {
        return new RegistrationResponse(
            cfg,
            c.get_bytes('evaluatedMessage', cfg.oprf.Noe),
            c.get_bytes('serverPublicKey', cfg.ake.Npk)
        )
    }
}

export class RegistrationRecord extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-5.1
    //
    // struct {
    //     uint8 client_public_key[Npk];
    //     uint8 masking_key[Nh];
    //     Envelope envelope;
    //   } RegistrationRecord;
    declare readonly clientPublicKey: Readonly<Uint8Array>
    declare readonly maskingKey: Readonly<Uint8Array>
    public readonly envelope: Readonly<Envelope>
    constructor(
        cfg: BaseConfig,
        clientPublicKey: Uint8Array,
        maskingKey: Uint8Array,
        envelope: Envelope
    ) {
        super()
        super.bytes('clientPublicKey', clientPublicKey, cfg.ake.Npk)
        super.bytes('maskingKey', maskingKey, cfg.hash.Nh)
        super.build(this)
        this.envelope = envelope
    }

    serialize(): Uint8Array {
        return joinAll(super.serialize(), this.envelope.serialize())
    }

    static deserialize(cfg: BaseConfig, c: Cursor): RegistrationRecord {
        return new RegistrationRecord(
            cfg,
            c.get_bytes('clientPublicKey', cfg.ake.Npk),
            c.get_bytes('maskingKey', cfg.hash.Nh),
            Envelope.deserialize(cfg, c)
        )
    }

    static async createFakeRecord(cfg: BaseConfig): Promise<RegistrationRecord> {
        const { publicKey: clientPublicKey } = await cfg.dh.generateKeyPair()
        const maskingKey = crypto.getRandomValues(new Uint8Array(cfg.hash.Nh))
        const zeroEnvelopeBytes = new Uint8Array(Envelope.sizeSerialized(cfg)).fill(0)
        const envelope = Envelope.deserialize(cfg, new Cursor(zeroEnvelopeBytes))

        return new RegistrationRecord(cfg, clientPublicKey, maskingKey, envelope)
    }
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-5.2.1
async function createRegistrationRequest(
    cfg: RegistrationClientConfig,
    password: Uint8Array
): Promise<{ request: RegistrationRequest; blind: OPRFScalar }> {
    const { blind, blindedElement } = await cfg.oprf.blind(password)
    const blindedMessage = blindedElement.serialize()
    const request = new RegistrationRequest(cfg, blindedMessage)

    return { request, blind }
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-5.2.2
async function createRegistrationResponse(
    cfg: OPRFServerConfig,
    request: RegistrationRequest,
    credentialIdentifier: Uint8Array,
    serverPublicKey: Uint8Array,
    oprfSeed: Uint8Array
): Promise<RegistrationResponse> {
    const seed = await cfg.kdf.expand(
        oprfSeed,
        joinAll(credentialIdentifier, LABELS.OprfKey),
        cfg.oprf.Nok
    )
    const oprfKey = await cfg.oprf.deriveOPRFKey(seed, LABELS.OPAQUE_DeriveKeyPair)
    const blindedElement = cfg.oprf.deserializeElement(request.blindedMessage)
    const evaluatedElement = await cfg.oprf.blindEvaluate(oprfKey, blindedElement)
    const evaluatedMessage = evaluatedElement.serialize()

    return new RegistrationResponse(cfg, evaluatedMessage, serverPublicKey)
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-5.2.3
async function finalizeRegistrationRequest(
    cfg: RegistrationClientConfig,
    password: Uint8Array,
    blind: OPRFScalar,
    response: RegistrationResponse,
    identities: IdentitiesBytes
): Promise<{
    record: RegistrationRecord
    exportKey: Uint8Array
}> {
    const { evaluatedMessage, serverPublicKey } = response
    const evaluatedElement = cfg.oprf.deserializeElement(evaluatedMessage)
    const oprfOutput = await cfg.oprf.finalize(password, blind, evaluatedElement)
    const stretchedOprfOutput = cfg.ksf.stretch(oprfOutput)
    const nosalt = new Uint8Array(cfg.hash.Nh)
    const randomizedPassword = await cfg.kdf.extract(
        nosalt,
        joinAll(oprfOutput, stretchedOprfOutput)
    )
    const { envelope, clientPublicKey, maskingKey, exportKey } = await store(
        cfg,
        randomizedPassword,
        serverPublicKey,
        identities
    )
    const record = new RegistrationRecord(cfg, clientPublicKey, maskingKey, envelope)

    return { record, exportKey }
}

export class RegistrationClient {
    private state?: { blind: OPRFScalar; password: Uint8Array }
    public readonly cfg: RegistrationClientConfig

    constructor(id: OpaqueID, ksf: KSFFn) {
        this.cfg = { ...configFromID(id), oprf: new OPRFClient(id), ksf }
    }

    clean() {
        delete this.state
    }

    async request(password: string): Promise<Result<RegistrationRequest>> {
        if (this.state) {
            return Result.Err(new Error('invoke RegistrationClient with a clean state'))
        }

        const te = new TextEncoder()
        const passwordBytes = te.encode(password)
        const { request, blind } = await createRegistrationRequest(this.cfg, passwordBytes)

        this.state = { blind, password: passwordBytes }

        return Result.Ok(request)
    }

    async finalize(
        response: RegistrationResponse,
        identities: Identities
    ): Promise<
        Result<{
            record: RegistrationRecord
            exportKey: Uint8Array
        }>
    > {
        if (!this.state) {
            return Result.Err(new Error('invoke RegistrationClient.request before finalize'))
        }

        const output = await finalizeRegistrationRequest(
            this.cfg,
            this.state.password,
            this.state.blind,
            response,
            identitiesToBytes(identities)
        )

        this.clean()

        return Result.Ok(output)
    }
}

export class RegistrationServer {
    public readonly cfg: OPRFServerConfig
    private readonly serverPublicKey: Uint8Array
    private readonly oprfSeed: Uint8Array

    constructor(id: OpaqueID, serverPublicKey: Uint8Array, oprfSeed: Uint8Array) {
        this.cfg = { ...configFromID(id), oprf: new OPRFServer(id) }
        this.serverPublicKey = checked_vector(serverPublicKey, this.cfg.ake.Npk)
        this.oprfSeed = checked_vector(oprfSeed, this.cfg.Nseed)
    }

    respond(
        credentialIdentifier: string,
        request: RegistrationRequest
    ): Promise<RegistrationResponse> {
        return createRegistrationResponse(
            this.cfg,
            request,
            new TextEncoder().encode(credentialIdentifier),
            this.serverPublicKey,
            this.oprfSeed
        )
    }
}

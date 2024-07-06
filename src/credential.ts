// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Result } from './util.js'
import { joinAll, xor } from './util.js'
import { LABELS } from './constants.js'
import type { AKEKeyPair, BaseConfig, KSFFn } from './deps.js'
import type { OPRFClientConfig, OPRFScalar, OPRFServerConfig } from './oprf.js'
import {
    Envelope,
    recover,
    type CleartextCredentials,
    type IdentitiesBytes
} from './key_recovery.js'
import type { RegistrationRecord } from './registration.js'
import { Cursor } from './serde.js'
import { Struct } from './serde.js'

export class CredentialRequest extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.3.1
    //
    // struct {
    //     uint8 blinded_message[Noe];
    //   } CredentialRequest;

    declare readonly blindedMessage: Readonly<Uint8Array>
    constructor(cfg: BaseConfig, blindedMessage: Uint8Array) {
        super()
        super.bytes('blindedMessage', blindedMessage, cfg.oprf.Noe)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): CredentialRequest {
        return new CredentialRequest(cfg, c.get_bytes('blindedMessage', cfg.oprf.Noe))
    }
}

export class CredentialResponse extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.3.1
    //
    // struct {
    //     uint8 evaluated_message[Noe];
    //     uint8 masking_nonce[Nn];
    //     uint8 masked_response[Npk + Nn + Nm];
    //   } CredentialResponse;

    declare readonly evaluatedMessage: Readonly<Uint8Array>
    declare readonly maskingNonce: Readonly<Uint8Array>
    declare readonly maskedResponse: Readonly<Uint8Array>
    constructor(
        cfg: BaseConfig,
        evaluatedMessage: Uint8Array,
        maskingNonce: Uint8Array,
        maskedResponse: Uint8Array
    ) {
        super()
        super.bytes('evaluatedMessage', evaluatedMessage, cfg.oprf.Noe)
        super.bytes('maskingNonce', maskingNonce, cfg.Nn)
        super.bytes('maskedResponse', maskedResponse, cfg.ake.Npk + cfg.Nn + cfg.mac.Nm)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): CredentialResponse {
        return new CredentialResponse(
            cfg,
            c.get_bytes('evaluatedMessage', cfg.oprf.Noe),
            c.get_bytes('maskingNonce', cfg.Nn),
            c.get_bytes('maskedResponse', cfg.ake.Npk + cfg.Nn + cfg.mac.Nm)
        )
    }
}

export type RegistrationClientConfig = OPRFClientConfig & { ksf: KSFFn }

export async function createCredentialRequest(
    cfg: RegistrationClientConfig,
    password: Uint8Array
): Promise<{
    request: CredentialRequest
    blind: OPRFScalar
}> {
    const { blind, blindedElement } = await cfg.oprf.blind(password)
    const blindedMessage = blindedElement.serialize()
    const request = new CredentialRequest(cfg, blindedMessage)

    return { request, blind }
}

export async function createCredentialResponse(
    cfg: OPRFServerConfig & { ake: AKEKeyPair },
    request: CredentialRequest,
    record: RegistrationRecord,
    credentialIdentifier: Uint8Array,
    oprfSeed: Uint8Array
): Promise<CredentialResponse> {
    const seed = await cfg.kdf.expand(
        oprfSeed,
        joinAll(credentialIdentifier, LABELS.OprfKey),
        cfg.oprf.Nok
    )
    const oprfKey = await cfg.oprf.deriveOPRFKey(seed, LABELS.OPAQUE_DeriveKeyPair)
    const blindedElement = cfg.oprf.deserializeElement(request.blindedMessage)
    const evaluatedElement = await cfg.oprf.blindEvaluate(oprfKey, blindedElement)
    const evaluatedMessage = evaluatedElement.serialize()
    const maskingNonce = crypto.getRandomValues(new Uint8Array(cfg.Nn))
    const credentialResponsePad = await cfg.kdf.expand(
        record.maskingKey,
        joinAll(maskingNonce, LABELS.CredentialResponsePad),
        cfg.ake.Npk + cfg.Nn + cfg.mac.Nm
    )
    const maskedResponse = xor(
        credentialResponsePad,
        joinAll(cfg.ake.publicKey, record.envelope.serialize())
    )

    return new CredentialResponse(cfg, evaluatedMessage, maskingNonce, maskedResponse)
}

export async function recoverCredentials(
    cfg: RegistrationClientConfig,
    password: Uint8Array,
    blind: OPRFScalar,
    response: CredentialResponse,
    identities: IdentitiesBytes
): Promise<
    Result<{
        clientPrivateKey: Uint8Array
        cleartextCredentials: CleartextCredentials
        exportKey: Uint8Array
    }>
> {
    const evaluatedElement = cfg.oprf.deserializeElement(response.evaluatedMessage)
    const oprfOutput = await cfg.oprf.finalize(password, blind, evaluatedElement)
    const stretchedOprfOutput = cfg.ksf.stretch(oprfOutput)
    const nosalt = new Uint8Array(cfg.hash.Nh)
    const randomizedPassword = await cfg.kdf.extract(
        nosalt,
        joinAll(oprfOutput, stretchedOprfOutput)
    )
    const maskingKey = await cfg.kdf.expand(randomizedPassword, LABELS.MaskingKey, cfg.hash.Nh)
    const credentialResponsePad = await cfg.kdf.expand(
        maskingKey,
        joinAll(response.maskingNonce, LABELS.CredentialResponsePad),
        cfg.ake.Npk + cfg.Nn + cfg.mac.Nm
    )
    const plaintext = xor(credentialResponsePad, response.maskedResponse)
    const serverPublicKey = plaintext.slice(0, cfg.ake.Npk)
    const envelopeBytes = plaintext.slice(cfg.ake.Npk)
    const envelope = Envelope.deserialize(cfg, new Cursor(envelopeBytes))

    return recover(cfg, randomizedPassword, serverPublicKey, envelope, identities)
}

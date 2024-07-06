// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Serializable } from '../src/deps.js'
import { configFromID } from '../src/config.js'
import { OpaqueID } from '../src/constants.js'
import { CredentialRequest, CredentialResponse } from '../src/credential.js'
import { Envelope } from '../src/key_recovery.js'
import {
    RegistrationRecord,
    RegistrationRequest,
    RegistrationResponse
} from '../src/registration.js'
import { AuthRequest, AuthResponse, KE1, KE2, KE3 } from '../src/ake_messages.js'
import { Cursor, type Deserializable } from '../src/serde.js'

function serdeClass<U, T extends Serializable>(u: U, name: string, a: Deserializable<U, T>, b: T) {
    test(`serde-${name}`, () => {
        const ser = b.serialize()
        const deser = a.deserialize(u, new Cursor(ser))
        const bytes = deser.serialize()
        expect(ser).toStrictEqual(bytes)
    })
}

describe.each([OpaqueID.P256, OpaqueID.P384, OpaqueID.P521])('%s', (id: OpaqueID) => {
    const cfg = configFromID(id)

    const credentialRequest = new CredentialRequest(cfg, new Uint8Array(cfg.oprf.Noe))
    serdeClass(cfg, 'CredentialRequest', CredentialRequest, credentialRequest)

    const credentialResponse = new CredentialResponse(
        cfg,
        new Uint8Array(cfg.oprf.Noe),
        new Uint8Array(cfg.Nn),
        new Uint8Array(cfg.ake.Npk + cfg.Nn + cfg.mac.Nm)
    )
    serdeClass(cfg, 'CredentialResponse', CredentialResponse, credentialResponse)

    const envelope = new Envelope(cfg, new Uint8Array(cfg.Nn), new Uint8Array(cfg.mac.Nm))
    serdeClass(cfg, 'Envelope', Envelope, envelope)

    serdeClass(
        cfg,
        'RegistrationRequest',
        RegistrationRequest,
        new RegistrationRequest(cfg, new Uint8Array(cfg.oprf.Noe))
    )

    serdeClass(
        cfg,
        'RegistrationResponse',
        RegistrationResponse,
        new RegistrationResponse(cfg, new Uint8Array(cfg.oprf.Noe), new Uint8Array(cfg.ake.Npk))
    )

    serdeClass(
        cfg,
        'RegistrationRecord',
        RegistrationRecord,
        new RegistrationRecord(
            cfg,
            new Uint8Array(cfg.ake.Npk),
            new Uint8Array(cfg.hash.Nh),
            envelope
        )
    )

    const authRequest = new AuthRequest(cfg, new Uint8Array(cfg.Nn), new Uint8Array(cfg.ake.Npk))
    serdeClass(cfg, 'AuthRequest', AuthRequest, authRequest)

    const authResponse = new AuthResponse(
        cfg,
        new Uint8Array(cfg.Nn),
        new Uint8Array(cfg.ake.Npk),
        new Uint8Array(cfg.mac.Nm)
    )
    serdeClass(cfg, 'AuthResponse', AuthResponse, authResponse)

    serdeClass(cfg, 'KE1', KE1, new KE1(credentialRequest, authRequest))
    serdeClass(cfg, 'KE2', KE2, new KE2(credentialResponse, authResponse))
    serdeClass(cfg, 'KE3', KE3, new KE3(cfg, new Uint8Array(cfg.mac.Nm)))
})

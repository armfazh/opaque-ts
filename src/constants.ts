// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Oprf } from '@cloudflare/voprf-ts'

export const LABELS = (() => {
    const te = new TextEncoder()
    return {
        AuthKey: te.encode('AuthKey'),
        ClientMAC: te.encode('ClientMAC'),
        CredentialResponsePad: te.encode('CredentialResponsePad'),
        ExportKey: te.encode('ExportKey'),
        HandshakeSecret: te.encode('HandshakeSecret'),
        MaskingKey: te.encode('MaskingKey'),
        OPAQUE: te.encode('OPAQUE-'),
        OPAQUE_DeriveDHKeyPair: te.encode('OPAQUE-DeriveDiffieHellmanKeyPair'),
        OPAQUE_DeriveKeyPair: te.encode('OPAQUE-DeriveKeyPair'),
        OprfKey: te.encode('OprfKey'),
        PrivateKey: te.encode('PrivateKey'),
        ServerMAC: te.encode('ServerMAC'),
        SessionKey: te.encode('SessionKey'),
        Version: te.encode('OPAQUEv1-')
    } as const
})()

export const OpaqueID = {
    P256: 'OPAQUE-3DH(P256,SHA256)',
    P384: 'OPAQUE-3DH(P384,SHA384)',
    P521: 'OPAQUE-3DH(P521,SHA512)'
} as const

export type OpaqueID = (typeof OpaqueID)[keyof typeof OpaqueID]

export const Params = {
    fromID(id: OpaqueID) {
        switch (id) {
            case OpaqueID.P256:
                return { hash: 'SHA-256', oprfID: Oprf.Suite.P256_SHA256 }
            case OpaqueID.P384:
                return { hash: 'SHA-384', oprfID: Oprf.Suite.P384_SHA384 }
            case OpaqueID.P521:
                return { hash: 'SHA-512', oprfID: Oprf.Suite.P521_SHA512 }
            default:
                throw new Error(`OpaqueID <${id}> is not supported`)
        }
    }
} as const

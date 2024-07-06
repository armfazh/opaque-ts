// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { getKeySizes, deriveKeyPair, generateKeyPair, Oprf } from '@cloudflare/voprf-ts'

import type { AKEKeyPair, BaseConfig } from './deps.js'
import { Params } from './constants.js'
import type { OpaqueID } from './constants.js'
import { Hash, Hkdf, HmacBuilder } from './kdf_mac_hash.js'
import { OPRFBase } from './oprf.js'
import { PrimeCurveDH } from './dh.js'

export function configFromID(id: OpaqueID): Readonly<BaseConfig> {
    const { hash, oprfID } = Params.fromID(id)
    return {
        Nn: 32,
        Nseed: 32,
        oprf: new OPRFBase(id),
        kdf: new Hkdf(hash),
        mac: new HmacBuilder(hash),
        hash: new Hash(hash),
        ake: getKeySizes(oprfID),
        dh: new PrimeCurveDH(oprfID)
    } as const
}

export const AKEKeys = {
    generateKeyPair: (id: OpaqueID): Promise<AKEKeyPair> =>
        generateKeyPair(Params.fromID(id).oprfID),
    deriveKeyPair: (id: OpaqueID, seed: Uint8Array): Promise<AKEKeyPair> =>
        deriveKeyPair(Oprf.Mode.OPRF, Params.fromID(id).oprfID, seed, new Uint8Array())
} as const

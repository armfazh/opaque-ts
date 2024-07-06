// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { deriveKeyPair, generateKeyPair, Oprf, type SuiteID } from '@cloudflare/voprf-ts'

import type { DHFn, DHKeyPair } from './deps.js'
import { LABELS } from './constants.js'

export class PrimeCurveDH implements DHFn {
    constructor(private readonly oprfID: SuiteID) {}

    generateKeyPair(): Promise<DHKeyPair> {
        return generateKeyPair(this.oprfID)
    }

    deriveKeyPair(seed: Uint8Array): Promise<DHKeyPair> {
        return deriveKeyPair(Oprf.Mode.OPRF, this.oprfID, seed, LABELS.OPAQUE_DeriveDHKeyPair)
    }

    genDH(k: Uint8Array, p: Uint8Array): Uint8Array {
        const gg = Oprf.getGroup(this.oprfID)
        const point = gg.desElt(p)
        const scalar = gg.desScalar(k)
        const kP = point.mul(scalar)

        return kP.serialize()
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Elt, Scalar, SuiteID } from '@cloudflare/voprf-ts'
import {
    Evaluation,
    EvaluationRequest,
    FinalizeData,
    OPRFClient as OPRFClientExternal,
    OPRFServer as OPRFServerExternal,
    Oprf,
    derivePrivateKey,
    getKeySizes
} from '@cloudflare/voprf-ts'

import type { OPRFClientFn, OPRFServerFn, OPRFFn, BaseConfig } from './deps.js'
import { Params, type OpaqueID } from './constants.js'

export type { Elt as OPRFElement, Scalar as OPRFScalar }
export type OPRFClientConfig = BaseConfig & { oprf: OPRFClientFn<Elt, Scalar> }
export type OPRFServerConfig = BaseConfig & { oprf: OPRFServerFn<Elt> }

export class OPRFBase implements OPRFFn {
    readonly ID: SuiteID
    readonly Noe: number
    readonly Nok: number

    constructor(id: OpaqueID) {
        const params = Params.fromID(id)
        this.ID = params.oprfID
        this.Noe = Oprf.getGroup(params.oprfID).eltSize(true)
        this.Nok = getKeySizes(params.oprfID).Nsk
    }

    deserializeElement(bytes: Uint8Array): Elt {
        return Oprf.getGroup(this.ID).desElt(bytes)
    }
}

export class OPRFClient extends OPRFBase implements OPRFFn, OPRFClientFn<Elt, Scalar> {
    private readonly client: OPRFClientExternal

    constructor(id: OpaqueID) {
        super(id)
        this.client = new OPRFClientExternal(this.ID)
    }

    async blind(input: Uint8Array): Promise<{ blind: Scalar; blindedElement: Elt }> {
        const [finData, evalReq] = await this.client.blind([input])

        return {
            blind: finData.blinds[0],
            blindedElement: evalReq.blinded[0]
        }
    }

    async finalize(input: Uint8Array, blind: Scalar, evaluatedElement: Elt): Promise<Uint8Array> {
        const finData = new FinalizeData([input], [blind], new EvaluationRequest([]))
        const evaluation = new Evaluation(Oprf.Mode.OPRF, [evaluatedElement])
        const outputs = await this.client.finalize(finData, evaluation)

        return outputs[0]
    }
}

export class OPRFServer extends OPRFBase implements OPRFFn, OPRFServerFn<Elt> {
    async blindEvaluate(oprfKey: Uint8Array, blindedElement: Elt): Promise<Elt> {
        const evaluations = await new OPRFServerExternal(this.ID, oprfKey).blindEvaluate(
            new EvaluationRequest([blindedElement])
        )

        return evaluations.evaluated[0]
    }

    deriveOPRFKey(seed: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
        return derivePrivateKey(Oprf.Mode.OPRF, this.ID, seed, info)
    }
}

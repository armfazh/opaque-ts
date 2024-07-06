// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { CredentialRequest, KE2 } from './messages.js'
import { AuthFinish, AuthRequest, KE1 } from './messages.js'
import { deriveKeys, preambleBuild, tripleDH_IKM } from './common.js'

import type { Config } from './config.js'
import { joinAll } from './util.js'

export class AKE3DHClient {
    private client_secret?: Uint8Array
    private ke1?: KE1

    constructor(private readonly config: Config) {}
}

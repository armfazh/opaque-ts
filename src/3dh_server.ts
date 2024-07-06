// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { ExpectedAuthResult } from './messages.js'

import type { Config } from './config.js'

export class AKE3DHServer {
    private expected?: ExpectedAuthResult

    constructor(private readonly config: Config) {}
}

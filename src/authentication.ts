// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { Result } from './util.js'
import type { AKEKeyPair, KSFFn } from './deps.js'
import type { OpaqueID } from './constants.js'
import type { Identities } from './key_recovery.js'
import { CleartextCredentials, identitiesToBytes } from './key_recovery.js'
import type { CredentialRequest, CredentialResponse } from './credential.js'
import {
    createCredentialRequest,
    createCredentialResponse,
    recoverCredentials
} from './credential.js'
import {
    OPRFClient,
    OPRFServer,
    type OPRFClientConfig,
    type OPRFScalar,
    type OPRFServerConfig
} from './oprf.js'
import type { RegistrationRecord } from './registration.js'
import type { KE1, KE3, AuthResponse } from './ake_messages.js'
import { KE2 } from './ake_messages.js'
import { AKEClient, AKEServer } from './ake.js'
import { configFromID } from './config.js'

export interface AKEClientFn {
    start(credentialRequest: CredentialRequest): Promise<Result<KE1>>
    finalize(
        cleartextCredentials: CleartextCredentials,
        clientPrivateKey: Uint8Array,
        ke2: KE2,
        context: Uint8Array
    ): Promise<Result<{ ke3: KE3; sessionKey: Uint8Array }>>
}

export interface AKEServerFn {
    respond(
        cleartextCredentials: CleartextCredentials,
        clientPublicKey: Uint8Array,
        ke1: KE1,
        credentialResponse: CredentialResponse,
        context: Uint8Array
    ): Promise<AuthResponse>
    finish(ke3: KE3): Result<{ sessionKey: Uint8Array }>
}

export class AuthenticationClient {
    private state?: { password: Uint8Array; blind: OPRFScalar }
    public readonly cfg: OPRFClientConfig & { ake: AKEClientFn; ksf: KSFFn }

    constructor(id: OpaqueID, ksf: KSFFn) {
        const base = configFromID(id)
        this.cfg = {
            ...base,
            oprf: new OPRFClient(id),
            ake: new AKEClient(base),
            ksf
        }
    }

    clean() {
        delete this.state
    }

    async generateKE1(password: string): Promise<Result<KE1>> {
        if (this.state) {
            return Result.Err(new Error('invoke generateKE1 using a clean state'))
        }

        const te = new TextEncoder()
        const passwordBytes = te.encode(password)
        const { request, blind } = await createCredentialRequest(this.cfg, passwordBytes)

        this.state = { password: passwordBytes, blind }

        return this.cfg.ake.start(request)
    }

    async generateKE3(
        ke2: KE2,
        identities: Identities,
        context = new Uint8Array()
    ): Promise<
        Result<{
            ke3: KE3
            sessionKey: Uint8Array
            exportKey: Uint8Array
        }>
    > {
        if (!this.state) {
            return Result.Err(new Error('should generate KE1 first'))
        }

        const creds = await recoverCredentials(
            this.cfg,
            this.state.password,
            this.state.blind,
            ke2.credentialResponse,
            identitiesToBytes(identities)
        )
        if (Result.isErr(creds)) {
            return creds
        }

        const { clientPrivateKey, cleartextCredentials, exportKey } = creds
        const result = await this.cfg.ake.finalize(
            cleartextCredentials,
            clientPrivateKey,
            ke2,
            context
        )
        if (Result.isErr(result)) {
            return result
        }

        const { ke3, sessionKey } = result

        this.clean()

        return Result.Ok({ ke3, sessionKey, exportKey })
    }
}

export class AuthenticationServer {
    readonly cfg: OPRFServerConfig & { ake: AKEServerFn & AKEKeyPair }

    constructor(id: OpaqueID, keypair: AKEKeyPair) {
        const base = configFromID(id)
        this.cfg = {
            ...base,
            oprf: new OPRFServer(id),
            ake: new AKEServer(base, keypair)
        }
    }

    async generateKE2(
        ke1: KE1,
        credentialIdentifier: string,
        record: RegistrationRecord,
        oprfSeed: Uint8Array,
        identities: Identities,
        context = new Uint8Array()
    ): Promise<KE2> {
        const credentialResponse = await createCredentialResponse(
            this.cfg,
            ke1.credentialRequest,
            record,
            new TextEncoder().encode(credentialIdentifier),
            oprfSeed
        )
        const cleartextCredentials = new CleartextCredentials(this.cfg, {
            serverPublicKey: this.cfg.ake.publicKey,
            clientPublicKey: record.clientPublicKey,
            ...identitiesToBytes(identities)
        })
        const authResponse = await this.cfg.ake.respond(
            cleartextCredentials,
            record.clientPublicKey,
            ke1,
            credentialResponse,
            context
        )

        return new KE2(credentialResponse, authResponse)
    }

    finish(ke3: KE3): Result<{ sessionKey: Uint8Array }> {
        return this.cfg.ake.finish(ke3)
    }
}

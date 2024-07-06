// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { AKEKeyPair, KSFFn } from './thecrypto.js'
import type { CredentialResponse, RegistrationResponse } from './messages.js'
import { CredentialRequest, Envelope, RegistrationRecord, RegistrationRequest } from './messages.js'
import { joinAll, xor } from './util.js'

import type { Config } from './config.js'

export class OpaqueCoreClient {
    constructor(
        public readonly config: Config,
        private ksf: KSFFn
    ) {}

    async createCredentialRequest(
        password: Uint8Array
    ): Promise<{ request: CredentialRequest; blind: Uint8Array }> {
        const { blindedElement: M, blind } = await this.config.oprf.blind(password)
        const request = new CredentialRequest(this.config, M)
        return { request, blind }
    }

    async recoverCredentials(
        password: Uint8Array,
        blind: Uint8Array,
        response: CredentialResponse,
        server_identity?: Uint8Array,
        client_identity?: Uint8Array
    ): Promise<
        | {
              client_ake_keypair: AKEKeyPair
              server_public_key: Uint8Array
              export_key: Uint8Array
          }
        | Error
    > {
        const y = await this.config.oprf.finalize(password, blind, response.evaluation)
        const nosalt = new Uint8Array(this.config.hash.Nh)
        const randomized_pwd = await this.config.kdf.extract(
            nosalt,
            joinAll([y, this.ksf.stretch(y)])
        )
        const masking_key = await this.config.kdf.expand(
            randomized_pwd,
            Uint8Array.from(LABELS.MaskingKey),
            this.config.hash.Nh
        )
        const Ne = Envelope.sizeSerialized(this.config)
        const credential_response_pad = await this.config.kdf.expand(
            masking_key,
            joinAll([response.masking_nonce, Uint8Array.from(LABELS.CredentialResponsePad)]),
            this.config.ake.Npk + Ne
        )
        const server_pub_key_enve = xor(credential_response_pad, response.masked_response)
        const server_public_key = server_pub_key_enve.slice(0, this.config.ake.Npk)
        const { Npk } = this.config.ake
        const envelope_bytes = server_pub_key_enve.slice(Npk, Npk + Ne)
        const envelope = Envelope.deserialize(this.config, Array.from(envelope_bytes))
        const rec = await recover(
            this.config,
            envelope,
            randomized_pwd,
            server_public_key,
            server_identity,
            client_identity
        )
        if (rec instanceof Error) {
            return rec
        }
        return { server_public_key, ...rec }
    }
}

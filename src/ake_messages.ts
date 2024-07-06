// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { joinAll } from './util.js'
import type { BaseConfig } from './deps.js'
import { CredentialRequest, CredentialResponse } from './credential.js'
import type { Cursor } from './serde.js'
import { Struct } from './serde.js'

export class AuthRequest extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.1
    //
    // struct {
    //     uint8 client_nonce[Nn];
    //     uint8 client_public_keyshare[Npk];
    //   } AuthRequest;
    declare readonly clientNonce: Readonly<Uint8Array>
    declare readonly clientPublicKeyshare: Readonly<Uint8Array>
    constructor(cfg: BaseConfig, clientNonce: Uint8Array, clientPublicKeyshare: Uint8Array) {
        super()
        super.bytes('clientNonce', clientNonce, cfg.Nn)
        super.bytes('clientPublicKeyshare', clientPublicKeyshare, cfg.ake.Npk)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): AuthRequest {
        return new AuthRequest(
            cfg,
            c.get_bytes('clientNonce', cfg.Nn),
            c.get_bytes('clientPublicKeyshare', cfg.ake.Npk)
        )
    }
}

export class KE1 {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.1
    //
    // struct {
    //     CredentialRequest credential_request;
    //     AuthRequest auth_request;
    //   } KE1;
    constructor(
        public readonly credentialRequest: CredentialRequest,
        public readonly authRequest: AuthRequest
    ) {}

    serialize(): Uint8Array {
        return joinAll(this.credentialRequest.serialize(), this.authRequest.serialize())
    }

    static deserialize(cfg: BaseConfig, c: Cursor): KE1 {
        return new KE1(CredentialRequest.deserialize(cfg, c), AuthRequest.deserialize(cfg, c))
    }
}

export class AuthResponse extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.1
    //
    // struct {
    //     uint8 server_nonce[Nn];
    //     uint8 server_public_keyshare[Npk];
    //     uint8 server_mac[Nm];
    //   } AuthResponse;
    declare readonly serverNonce: Readonly<Uint8Array>
    declare readonly serverPublicKeyshare: Readonly<Uint8Array>
    declare readonly serverMac: Readonly<Uint8Array>
    constructor(
        cfg: BaseConfig,
        serverNonce: Uint8Array,
        serverPublicKeyshare: Uint8Array,
        serverMac: Uint8Array
    ) {
        super()
        super.bytes('serverNonce', serverNonce, cfg.Nn)
        super.bytes('serverPublicKeyshare', serverPublicKeyshare, cfg.ake.Npk)
        super.bytes('serverMac', serverMac, cfg.mac.Nm)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): AuthResponse {
        return new AuthResponse(
            cfg,
            c.get_bytes('serverNonce', cfg.Nn),
            c.get_bytes('serverPublicKeyshare', cfg.ake.Npk),
            c.get_bytes('serverMac', cfg.mac.Nm)
        )
    }
}

export class KE2 {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.1
    //
    // struct {
    //     CredentialResponse credential_response;
    //     AuthResponse auth_response;
    //   } KE2;
    constructor(
        public readonly credentialResponse: CredentialResponse,
        public readonly authResponse: AuthResponse
    ) {}

    serialize(): Uint8Array {
        return joinAll(this.credentialResponse.serialize(), this.authResponse.serialize())
    }

    static deserialize(cfg: BaseConfig, c: Cursor): KE2 {
        return new KE2(CredentialResponse.deserialize(cfg, c), AuthResponse.deserialize(cfg, c))
    }
}

export class KE3 extends Struct {
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-opaque-16#section-6.1
    //
    // struct {
    //     uint8 client_mac[Nm];
    //   } KE3;
    declare readonly clientMac: Readonly<Uint8Array>
    constructor(cfg: BaseConfig, clientMac: Uint8Array) {
        super()
        super.bytes('clientMac', clientMac, cfg.mac.Nm)
        super.build(this)
    }

    static deserialize(cfg: BaseConfig, c: Cursor): KE3 {
        return new KE3(cfg, c.get_bytes('clientMac', cfg.mac.Nm))
    }
}

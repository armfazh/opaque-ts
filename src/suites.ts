// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

// export class OpaqueConfig {
//     readonly constants: {
//         readonly Nn: number
//         readonly Nseed: number
//     }

//     readonly oprf: OPRFFn

//     readonly hash: HashFn

//     readonly mac: MACFn

//     readonly kdf: KDFFn

//     readonly ake: AKEFn

//     readonly ksf: KSFFn

//     constructor(public readonly opaqueID: OpaqueID) {
//         let oprfID: SuiteID
//         switch (opaqueID) {
//             case OpaqueID.OPAQUE_P256:
//                 oprfID = Oprf.Suite.P256_SHA256
//                 break
//             case OpaqueID.OPAQUE_P384:
//                 oprfID = Oprf.Suite.P384_SHA384
//                 break
//             case OpaqueID.OPAQUE_P521:
//                 oprfID = Oprf.Suite.P521_SHA512
//                 break
//             default:
//                 throw new Error(`invalid OpaqueID ${opaqueID}`)
//         }

//         this.constants = { Nn: 32, Nseed: 32 }
//         this.oprf = new OPRFBaseMode(oprfID)
//         this.hash = new Hash(this.oprf.hash)
//         this.mac = new Hmac(this.hash.name)
//         this.kdf = new Hkdf(this.hash.name)
//         this.ake = new AKE3DH(oprfID)
//         this.ksf = IdentityKSFFn
//     }

//     static fromString(opaqueID: string): Result<Readonly<Config>, Error> {
//         if (!Object.values<string>(OpaqueID).includes(opaqueID)) {
//             return Err(new Error(`OpaqueID ${opaqueID} not supported`))
//         }
//         return Ok(new OpaqueConfig(opaqueID as OpaqueID))
//     }

//     toString(): string {
//         return `${this.opaqueID} = {` + `OPRF: ${this.oprf.name}, ` + `Hash: ${this.hash.name}}`
//     }
// }

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { configFromID } from '../src/config.js'

import type { KSFFn } from '../src/index.js'
import {
    AKEKeys,
    RegistrationClient,
    RegistrationServer,
    RegistrationRecord,
    OpaqueID,
    AuthenticationClient,
    AuthenticationServer,
    RegistrationRequest,
    Cursor,
    RegistrationResponse,
    KE1,
    KE3,
    KE2
} from '../src/index.js'

import { KVStorage, expectNotError } from './common.js'

interface inputTest {
    id: OpaqueID
    database: KVStorage
    password: string
    clientIdentity: string
    serverIdentity: string
    credentialIdentifier: string
    context: string
    akeKeySeed: Uint8Array
    oprfSeed: Uint8Array
    ksf: KSFFn
}

interface outputTest {
    record?: RegistrationRecord
    exportKey?: Uint8Array
}

async function test_registration(input: inputTest, output: outputTest): Promise<boolean> {
    const { id, ksf, password, serverIdentity, clientIdentity, credentialIdentifier, database } =
        input
    // Client
    const client = new RegistrationClient(id, ksf)
    const request = await client.request(password)
    expectNotError(request)
    const serReq = request.serialize()

    // Client        request         Server
    //           ------------->>>

    // Server
    const keys = await AKEKeys.deriveKeyPair(id, input.akeKeySeed)
    const server = new RegistrationServer(id, keys.publicKey, input.oprfSeed)

    const deserReq = RegistrationRequest.deserialize(server.cfg, new Cursor(serReq))
    const response = await server.respond(input.credentialIdentifier, deserReq)
    expectNotError(response)
    const serRes = response.serialize()

    // Client        response        Server
    //           <<<-------------

    // Client
    const deserRes = RegistrationResponse.deserialize(client.cfg, new Cursor(serRes))
    const rec = await client.finalize(deserRes, { serverIdentity, clientIdentity })
    expectNotError(rec)

    const { record, exportKey } = rec
    const serRec = record.serialize()
    // Client        record          Server
    //           ------------->>>

    // Server
    const deserRec = RegistrationRecord.deserialize(server.cfg, new Cursor(serRec))
    const success = database.store(credentialIdentifier, deserRec.serialize())
    // Client        success         Server
    //           <<<-------------

    expect(success).toBe(true)

    output.exportKey = exportKey
    output.record = deserRec

    return true
}

async function test_authentication(input: inputTest, output: outputTest): Promise<boolean> {
    expect(output.record).toBeDefined()
    expect(output.exportKey).toBeDefined()

    const { id, ksf, password, serverIdentity, clientIdentity, credentialIdentifier, database } =
        input

    // Client
    const client = new AuthenticationClient(id, ksf)
    const ke1 = await client.generateKE1(password)
    expectNotError(ke1)
    const serKE1 = ke1.serialize()

    // Client        ke1         Server
    //           ------------->>>

    // Server
    const credFileBytes = database.lookup(credentialIdentifier)
    expect(credFileBytes).not.toBe(false)

    if (typeof credFileBytes === 'boolean') {
        throw new Error('client not registered in database')
    }

    // const credential_file = CredentialFile.deserialize(cfg, Array.from(credFileBytes))
    // expect(credential_file.credential_identifier).toBe(credential_identifier)
    // expect(credential_file.client_identity).toBe(client_identity)

    const keys = await AKEKeys.deriveKeyPair(id, input.akeKeySeed)
    const server = new AuthenticationServer(id, keys)

    const deserKE1 = KE1.deserialize(server.cfg, new Cursor(serKE1))
    expect(deserKE1).toStrictEqual(ke1)

    const record = RegistrationRecord.deserialize(server.cfg, new Cursor(credFileBytes))
    const ke2 = await server.generateKE2(deserKE1, credentialIdentifier, record, input.oprfSeed, {
        serverIdentity,
        clientIdentity
    })
    const serKE2 = ke2.serialize()

    // Client           ke2          Server
    //           <<<-------------        |_ stores expected

    // Client
    const deserKE2 = KE2.deserialize(client.cfg, new Cursor(serKE2))
    expect(deserKE2).toStrictEqual(ke2)

    const finClient = await client.generateKE3(deserKE2, { serverIdentity, clientIdentity })
    expectNotError(finClient)

    const { ke3, sessionKey: sessionKeyClient, exportKey } = finClient
    expect(exportKey).toBeDefined()
    const serKE3 = ke3.serialize()

    // Client           ke3          Server
    //           ------------->>>       |_ recovers expected

    // Server
    const deserKE3 = KE3.deserialize(server.cfg, new Cursor(serKE3))
    expect(deserKE3).toStrictEqual(ke3)

    const finServer = server.finish(deserKE3)
    expectNotError(finServer)

    // At the end, server and client MUST arrive to the same session key.
    const { sessionKey: sessionKeyServer } = finServer
    expect(sessionKeyClient).toStrictEqual(sessionKeyServer)

    return true
}

describe.each([OpaqueID.P256, OpaqueID.P384, OpaqueID.P521])('%s', (id: OpaqueID) => {
    let input: inputTest
    let output: outputTest

    beforeAll(() => {
        const cfg = configFromID(id)
        input = {
            id,
            password: 'my favorite password123',
            clientIdentity: 'user_identifier@example.com',
            serverIdentity: 'server.opaque.example.com',
            credentialIdentifier: 'client_identifier_defined_by_server',
            context: 'context is a public, shared string',
            database: new KVStorage(),
            ksf: { name: 'identity', stretch: (x) => x },
            akeKeySeed: crypto.getRandomValues(new Uint8Array(cfg.Nseed)),
            oprfSeed: crypto.getRandomValues(new Uint8Array(cfg.Nseed))
        }
        output = {}
    })

    test('registration', async () => {
        expect(await test_registration(input, output)).toBe(true)
    })

    test('authentication', async () => {
        expect(await test_authentication(input, output)).toBe(true)
    })
})

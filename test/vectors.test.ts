// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import { jest } from '@jest/globals'
import { readFileSync } from 'node:fs'
import { unzipSync } from 'node:zlib'
import { OPRFClient, Oprf } from '@cloudflare/voprf-ts'

import {
    AuthenticationClient,
    AuthenticationServer,
    RegistrationClient,
    RegistrationServer,
    RegistrationRecord,
    OpaqueID,
    type KSFFn,
    Cursor,
    RegistrationRequest,
    RegistrationResponse,
    KE1,
    KE2,
    KE3
} from '../src/index.js'
import { Params } from '../src/constants.js'
import { configFromID } from '../src/config.js'
import { PrimeCurveDH } from '../src/dh.js'
import { Envelope } from '../src/key_recovery.js'

import {
    expectToBeError,
    expectNotError,
    expectToBeDefined,
    KVStorage,
    toHex,
    fromHex,
    fromHexString,
    notNullHex,
    notNullHexString
} from './common.js'

interface Vector {
    config: Configuration
    inputs: Inputs
    intermediates: Intermediates
    outputs: Outputs
}

interface Configuration {
    Context: string
    Fake: string
    Group: string
    Hash: string
    KDF: string
    KSF: string
    MAC: string
    Name: string
    Nh: string
    Nm: string
    Nok: string
    Npk: string
    Nsk: string
    Nx: string
    OPRF: string
}

interface Inputs {
    blind_login: string
    blind_registration: string
    client_identity?: string
    client_keyshare_seed: string
    client_nonce: string
    client_private_key?: string
    client_public_key?: string
    credential_identifier: string
    envelope_nonce: string
    masking_nonce: string
    masking_key?: string
    oprf_seed: string
    password: string
    server_identity?: string
    server_keyshare_seed: string
    server_nonce: string
    server_private_key: string
    server_public_key: string
    KE1?: string
}

interface Intermediates {
    auth_key: string
    client_mac_key: string
    client_public_key: string
    envelope: string
    handshake_secret: string
    masking_key: string
    oprf_key: string
    randomized_password: string
    server_mac_key: string
}

interface Outputs {
    KE1: string
    KE2: string
    KE3: string
    export_key: string
    registration_request: string
    registration_response: string
    registration_upload: string
    session_key: string
}

function createMocks(vector: Vector, input: inputTest) {
    jest.clearAllMocks()

    // Setup Server creates a fake record.
    const source = input.isFake ? vector.inputs : vector.intermediates
    jest.spyOn(PrimeCurveDH.prototype, 'generateKeyPair').mockReturnValueOnce(
        Promise.resolve({
            privateKey: new Uint8Array(), // as privateKey is not used.
            publicKey: notNullHex(source.client_public_key)
        })
    )
    jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(notNullHex(source.masking_key))

    // Registration Client

    if (!input.isFake) {
        // Creates a mock for OPRFClient.randomBlinder method to
        // inject the blind value given by the test vector.
        jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(() => {
            const blind = notNullHex(vector.inputs.blind_registration)
            const group = Oprf.getGroup(Params.fromID(input.id).oprfID)
            return Promise.resolve(group.desScalar(blind))
        })
        jest.spyOn(crypto, 'getRandomValues').mockReturnValueOnce(
            notNullHex(vector.inputs.envelope_nonce)
        )
    }

    // Authentication Client
    jest.spyOn(OPRFClient.prototype, 'randomBlinder').mockImplementationOnce(() => {
        const blind = notNullHex(vector.inputs.blind_login)
        const group = Oprf.getGroup(Params.fromID(input.id).oprfID)
        return Promise.resolve(group.desScalar(blind))
    })
    jest.spyOn(crypto, 'getRandomValues')
        .mockReturnValueOnce(notNullHex(vector.inputs.client_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.client_keyshare_seed))

    // Authentication Server
    jest.spyOn(crypto, 'getRandomValues')
        .mockReturnValueOnce(notNullHex(vector.inputs.masking_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.server_nonce))
        .mockReturnValueOnce(notNullHex(vector.inputs.server_keyshare_seed))
}

interface inputsRaw {
    password: string
    credentialIdentifier: string
    server_private_key: Uint8Array
    server_public_key: Uint8Array
    oprfSeed: Uint8Array
    masking_key: Uint8Array
    client_public_key: Uint8Array
    client_private_key: Uint8Array
    context: Uint8Array
    isFake: boolean
    ksf: KSFFn
}

interface inputsRawOpt {
    serverIdentity?: string
    clientIdentity?: string
    ke1?: Uint8Array
}

function getTestInputs(vector: Vector): inputsRaw & inputsRawOpt {
    const opt: inputsRawOpt = {}
    if (vector.inputs.client_identity) {
        opt.clientIdentity = fromHexString(vector.inputs.client_identity)
    }
    if (vector.inputs.server_identity) {
        opt.serverIdentity = fromHexString(vector.inputs.server_identity)
    }
    if (vector.inputs.KE1) {
        opt.ke1 = fromHex(vector.inputs.KE1)
    }

    return {
        client_private_key: notNullHex(vector.inputs.client_private_key),
        client_public_key: notNullHex(vector.inputs.client_public_key),
        server_private_key: fromHex(vector.inputs.server_private_key),
        server_public_key: fromHex(vector.inputs.server_public_key),
        password: notNullHexString(vector.inputs.password),
        credentialIdentifier: fromHexString(vector.inputs.credential_identifier),
        oprfSeed: fromHex(vector.inputs.oprf_seed),
        masking_key: notNullHex(vector.inputs.masking_key),
        context: fromHex(vector.config.Context),
        isFake: vector.config.Fake === 'True',
        ksf: { name: 'Identity', stretch: (x) => x },
        ...opt
    }
}

interface inputTest extends inputsRaw, inputsRawOpt {
    id: OpaqueID
    database: KVStorage
}

const FAKE_CREDENTIAL_IDENTIFIER = 'FAKE_CREDENTIAL_IDENTIFIER'
// const FAKE_CLIENT_IDENTITY = 'FAKE_CLIENT_IDENTITY'

async function test_setup(input: inputTest, vector: Vector): Promise<boolean> {
    const { id, database, isFake } = input
    const cfg = configFromID(id)
    // To prevent Client enumeration, the server stores a fake record in
    // advance to be use when a non-registered user tries to login.
    const fakeRecord = await RegistrationRecord.createFakeRecord(cfg)

    const source = isFake ? vector.inputs : vector.intermediates
    expect(toHex(fakeRecord.clientPublicKey)).toBe(source.client_public_key)
    expect(toHex(fakeRecord.maskingKey)).toBe(source.masking_key)

    const fakeEnvelope = fakeRecord.envelope.serialize()
    expect(fakeEnvelope.length).toBe(Envelope.sizeSerialized(cfg))
    expect(fakeEnvelope.every((byte) => byte === 0)).toBe(true)

    const dbDefault = database.set_default(FAKE_CREDENTIAL_IDENTIFIER, fakeRecord.serialize())
    expect(dbDefault).toBe(true)

    return true
}

function test_fake_registration(
    _client: RegistrationClient,
    _server: RegistrationServer,
    _input: inputTest,
    _vector: Vector
): Promise<boolean> {
    // This is a NOP since the Client never registers a password.
    return Promise.resolve(true)
}

async function test_real_registration(
    client: RegistrationClient,
    server: RegistrationServer,
    input: inputTest,
    vector: Vector
): Promise<boolean> {
    const { password, database, serverIdentity, clientIdentity, credentialIdentifier } = input

    // Client
    const request = await client.request(password)
    expectNotError(request)
    const serReq = request.serialize()
    expect(toHex(serReq)).toBe(vector.outputs.registration_request)
    // Client     registration request      Server
    //           --------------------->>>

    // Server
    const deserReq = RegistrationRequest.deserialize(server.cfg, new Cursor(serReq))
    const response = await server.respond(credentialIdentifier, deserReq)
    expectNotError(response)
    const serRes = response.serialize()
    expect(toHex(serRes)).toBe(vector.outputs.registration_response)
    // Client     registration response     Server
    //           <<<---------------------

    // Client
    const deserRes = RegistrationResponse.deserialize(client.cfg, new Cursor(serRes))
    const rec = await client.finalize(deserRes, { serverIdentity, clientIdentity })
    expectNotError(rec)

    const { record, exportKey } = rec
    const serRec = record.serialize()
    expect(toHex(serRec)).toBe(vector.outputs.registration_upload)
    expect(toHex(exportKey)).toBe(vector.outputs.export_key)
    // Client            record             Server
    //           --------------------->>>

    // Server
    const deserRec = RegistrationRecord.deserialize(server.cfg, new Cursor(serRec))
    const success = database.store(credentialIdentifier, deserRec.serialize())
    expect(success).toBe(true)
    // Client             success           Server
    //           <<<---------------------

    return true
}

async function test_fake_login(
    client: AuthenticationClient,
    server: AuthenticationServer,
    input: inputTest,
    vector: Vector
): Promise<boolean> {
    const {
        password,
        database,
        oprfSeed,
        serverIdentity,
        clientIdentity,
        credentialIdentifier,
        context
    } = input

    // Client
    const ke1 = await client.generateKE1(password)
    expectNotError(ke1)

    const serKE1 = ke1.serialize()
    expect(toHex(serKE1)).toBe(vector.inputs.KE1)
    // Client          ke1           Server
    //           ------------->>>

    // Server
    const recordBytes = database.lookup_or_default(credentialIdentifier)
    const record = RegistrationRecord.deserialize(server.cfg, new Cursor(recordBytes))
    // expect(credential_file.credential_identifier).toBe(FAKE_CREDENTIAL_IDENTIFIER)
    // expect(credential_file.client_identity).toBe(FAKE_CLIENT_IDENTITY)

    // Set the inputs from the allegedly-register client.
    // credential_file.credential_identifier = credential_identifier
    // credential_file.client_identity = client_identity

    const deserKE1 = KE1.deserialize(server.cfg, new Cursor(serKE1))
    const ke2 = await server.generateKE2(
        deserKE1,
        credentialIdentifier,
        record,
        oprfSeed,
        {
            serverIdentity,
            clientIdentity
        },
        context
    )

    const serKE2 = ke2.serialize()
    expect(toHex(serKE2)).toBe(vector.outputs.KE2)

    // Client           ke2          Server
    //           <<<-------------

    // Client
    const deserKE2 = KE2.deserialize(client.cfg, new Cursor(serKE2))
    const finClient = await client.generateKE3(
        deserKE2,
        { serverIdentity, clientIdentity },
        context
    )
    expectToBeError(finClient)
    expect(finClient.message).toBe('EnvelopeRecoveryError')

    return true
}

async function test_real_login(
    client: AuthenticationClient,
    server: AuthenticationServer,
    input: inputTest,
    vector: Vector
): Promise<boolean> {
    const {
        password,
        database,
        oprfSeed,
        serverIdentity,
        clientIdentity,
        credentialIdentifier,
        context
    } = input

    // Client
    const ke1 = await client.generateKE1(password)
    expectNotError(ke1)

    const serKE1 = ke1.serialize()
    expect(toHex(serKE1)).toBe(vector.outputs.KE1)
    // Client          ke1           Server
    //           ------------->>>

    // Server
    const recordBytes = database.lookup_or_default(credentialIdentifier)
    expect(recordBytes).not.toBe(false)

    const record = RegistrationRecord.deserialize(server.cfg, new Cursor(recordBytes))
    // expect(credential_file.credential_identifier).toBe(credential_identifier)
    // expect(credential_file.client_identity).toBe(client_identity)

    const deserKE1 = KE1.deserialize(server.cfg, new Cursor(serKE1))
    const ke2 = await server.generateKE2(
        deserKE1,
        credentialIdentifier,
        record,
        oprfSeed,
        {
            serverIdentity,
            clientIdentity
        },
        context
    )

    const serKE2 = ke2.serialize()
    expect(toHex(serKE2)).toBe(vector.outputs.KE2)

    // Client           ke2          Server
    //           <<<-------------

    // Client
    const deserKE2 = KE2.deserialize(client.cfg, new Cursor(serKE2))
    const finClient = await client.generateKE3(
        deserKE2,
        { serverIdentity, clientIdentity },
        context
    )
    expectNotError(finClient)

    const { ke3, exportKey } = finClient
    const serKE3 = ke3.serialize()
    expect(toHex(serKE3)).toBe(vector.outputs.KE3)
    expect(toHex(exportKey)).toBe(vector.outputs.export_key)
    expect(toHex(finClient.sessionKey)).toBe(vector.outputs.session_key)
    // Client           ke3          Server
    //           ------------->>>

    // Server
    const deserKE3 = KE3.deserialize(server.cfg, new Cursor(serKE3))
    const finServer = server.finish(deserKE3)
    expectNotError(finServer)
    expect(toHex(finServer.sessionKey)).toBe(vector.outputs.session_key)

    return true
}

function read_test_vectors(): Array<Vector> {
    const filename = './test/testdata/vectors_v16.json.gz'
    try {
        const file = readFileSync(filename)
        const json = unzipSync(file)
        const vectors = JSON.parse(json.toString()) as Array<Vector>
        return vectors
    } catch (error) {
        console.error(`Error reading ${filename}: ${error}`)
        process.abort()
    }
}

describe.each(read_test_vectors())('test-vector-$#', (vector: Vector) => {
    const id = Object.values(OpaqueID).find((id) => Params.fromID(id).oprfID === vector.config.OPRF)
    const vecInputs = getTestInputs(vector)
    const testCase = vecInputs.isFake ? 'fake' : 'real'
    const describe_or_skip = id ? describe : describe.skip

    describe_or_skip(vector.config.OPRF, () => {
        let input: inputTest

        beforeAll(() => {
            expectToBeDefined(id)
            input = { ...vecInputs, id, database: new KVStorage() }
            createMocks(vector, input)
        })

        test('Setup', async () => {
            expect(input.ksf.name).toBe(vector.config.KSF)
            expect(await test_setup(input, vector)).toBe(true)
        })

        test(`Registration (${testCase})`, async () => {
            const test_registration = input.isFake ? test_fake_registration : test_real_registration
            const client = new RegistrationClient(input.id, input.ksf)
            const server = new RegistrationServer(input.id, input.server_public_key, input.oprfSeed)

            expect(await test_registration(client, server, input, vector)).toBe(true)
        })

        test(`Authentication (${testCase})`, async () => {
            const test_login = input.isFake ? test_fake_login : test_real_login
            const client = new AuthenticationClient(input.id, input.ksf)
            const server = new AuthenticationServer(input.id, {
                publicKey: input.server_public_key,
                privateKey: input.server_private_key
            })
            expect(await test_login(client, server, input, vector)).toBe(true)
        })
    })
})

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause

import type { Serializable } from './deps'

export abstract class Struct implements Serializable {
    #list: Array<{
        field: string
        prefix: Uint8Array
        vector: Uint8Array
        interval: [start: number, end: number]
    }> = []
    #byteLength: number = 0
    #serialized: Uint8Array = new Uint8Array()

    protected build<T extends Struct>(childClass: T) {
        this.#serialized = new Uint8Array(new ArrayBuffer(this.#byteLength))
        let offset = 0
        for (const item of this.#list) {
            this.#serialized.set(item.prefix, offset)
            offset += item.prefix.length

            this.#serialized.set(item.vector, offset)
            offset += item.vector.length

            Object.defineProperty(childClass, item.field, {
                get() {
                    return childClass.#serialized.slice(...item.interval)
                }
            })
        }

        this.#list = []
    }

    protected bytes(field: string, vector: Uint8Array, length: number) {
        if (vector.length !== length) {
            throw new Error(`length of ${field} is ${vector.length} expected ${length}`)
        }
        this.#list.push({
            field,
            vector,
            prefix: new Uint8Array(),
            interval: [this.#byteLength, (this.#byteLength += vector.length)]
        })
    }
    protected u16_prefixed_bytes(field: string, vector: Uint8Array) {
        const BITS = 16
        const MAX = 1 << BITS
        if (vector.length >= MAX) {
            throw new Error(`length of ${field} is ${vector.length} out of range [0,2^${BITS}-1]`)
        }
        const prefix = new Uint8Array(2)
        new DataView(prefix.buffer).setUint16(0, vector.length)
        this.#list.push({
            field,
            vector,
            prefix,
            interval: [this.#byteLength + 2, (this.#byteLength += 2 + vector.length)]
        })
    }

    serialize(): Uint8Array {
        return this.#serialized.slice()
    }
}

export class Cursor {
    #offset: number = 0
    constructor(private data: Uint8Array) {}

    get_bytes(field: string, length: number): Uint8Array {
        const vector = this.data.slice(this.#offset, this.#offset + length)
        if (vector.length !== length) {
            throw new Error(`length of ${field} is ${vector.length} expected ${length}`)
        }
        this.#offset += length

        return vector
    }

    get_u16_prefixed_bytes(field: string): Uint8Array {
        const view = new DataView(this.data.buffer)
        const prefix = view.getUint16(this.#offset)
        const BITS = 16
        const MAX = 1 << BITS
        if (prefix >= MAX) {
            throw new Error(`prefix equal to ${prefix} is out of range [0,2^${BITS}-1]`)
        }
        this.#offset += 2

        return this.get_bytes(field, prefix)
    }
}

export interface Deserializable<U, T> {
    deserialize(u: U, c: Cursor): T
}

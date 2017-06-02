# qbox

TweetNaCl-based Quantum Transitional Hybrid Crypto.

Currently implements NTRU, as well as a low-level library for building other quantum transitional cryptographic constructions based on TweetNaCl.

## Installation

	npm install tweetnacl qbox

## Usage

All API functions accept and return bytes as `Uint8Array`s.  If you need to
encode or decode strings, use functions from
<https://github.com/dchest/tweetnacl-util-js> or one of the more robust codec
packages.

In Node.js v4 and later `Buffer` objects are backed by `Uint8Array`s, so you
can freely pass them to TweetNaCl.js functions as arguments. The returned
objects are still `Uint8Array`s, so if you need `Buffer`s, you'll have to
convert them manually; make sure to convert using copying: `new Buffer(array)`,
instead of sharing: `new Buffer(array.buffer)`, because some functions return
subarrays of their buffers.

### Public-key authenticated encryption with NTRU confidentiality (ntruBox)

Implements *x25519-ntru-xsalsa20-poly1305*.

The result of `nacl.box.before` (ECDH) is appended with 106 bytes of random key material before being hashed and truncated to 32 bytes. Random bytes are encapsulated using NTRU.

This construction provides pre-quantum authenticity via x25519 and post-quantum confidentiality via NTRU. The use of key encapsulation with max-width random key material removes the need to use any padding algorithm.

	const nacl = require('tweetnacl')
	const ntruBox = require('qbox').ntru(nacl)

#### ntruBox.keyPair()

Generates a new random key pair (x25519 and NTRU combined) for box and returns it as an object with
`publicKey` and `secretKey` members:

    {
       publicKey: ...,  // Uint8Array with 1059-byte public key
       secretKey: ...   // Uint8Array with 1152-byte secret key
    }

The NTRU component of the key is only used when provided as the publicKey in ntruBox and ntruBox.before, or as the secretKey in ntruBox.open and ntruBox.open.before.

#### ntruBox.keyPair.sendOnly()

Generates a new random key pair (x25519) for sending only and returns it as an object with
`publicKey` and `secretKey` members:

    {
       publicKey: ...,  // Uint8Array with 32-byte public key
       secretKey: ...   // Uint8Array with 32-byte secret key
    }

A sendOnly key can be provided as the secretKey in ntruBox and ntruBox.before, or as the publicKey in ntruBox.open and ntruBox.open.before. 

#### ntruBox(message, nonce, theirPublicKey, mySecretKey)

Encrypts and authenticates message using peer's public key, our secret key, and
the given nonce, which must be unique for each distinct message for a key pair.

Returns an encrypted and authenticated message, which is `ntruBox.overheadLength` longer than the original message, as well as NTRU-encapsulated key material for calculating the shared key on the receiver's side.

	{
       box: ...,  // Uint8Array with encrypted and authenticated message
       kem: ...   // Uint8Array with 1022-byte NTRU-encapsulated key material
	}

#### ntruBox.open(box, nonce, theirPublicKey, mySecretKey, kem)

Authenticates and decrypts the given box with peer's public key, our secret key, kem and the given nonce.

Returns the original message, or `false` if authentication fails.

#### ntruBox.before(theirPublicKey, mySecretKey)

Returns a precomputed shared key which can be used in `ntruBox.after` or `ntruBox.open.after`, as well as NTRU-encapsulated key material for calculating the shared key on the receiver's side.

	{
       sharedKey: ...,  // Uint8Array with 32-byte shared key
       kem: ...         // Uint8Array with 1022-byte NTRU-encapsulated key material
	}

#### ntruBox.open.before(theirPublicKey, mySecretKey, kem)

Returns a precomputed shared key which can be used in `ntruBox.after` or `ntruBox.open.after`.

#### ntruBox.after(message, nonce, sharedKey)

Same as `ntruBox`, but uses a shared key precomputed with `ntruBox.before` or `ntruBox.open.before`.

#### ntruBox.open.after(box, nonce, sharedKey)

Same as `ntruBox.open`, but uses a shared key precomputed with `ntruBox.before` or `ntruBox.open.before`.

#### ntruBox.publicKeyLength = 1059

Length of public key in bytes.

#### ntruBox.secretKeyLength = 1152

Length of secret key in bytes.

#### ntruBox.sharedKeyLength = 32

Length of precomputed shared key in bytes.

#### ntruBox.kemLength = 1022

Length of NTRU-encapsulated key material in bytes.

#### ntruBox.nonceLength = 24

Length of nonce in bytes.

#### ntruBox.overheadLength = 16

Length of overhead added to box compared to original message.

### Low-level primitive for mixing nacl.box with additional key material (qbox)

This component is used to build quantum-transitional constructions based on `nacl.box`

	// tweetnacl dependency is injected
	module.exports = (nacl) => {
       const qbox = require('qbox').lowlevel(nacl)

       // define your quantum-transitional module here
	}

#### qbox(message, nonce, theirPublicKey, mySecretKey, extraKeyMaterial)

Encrypts and authenticates message using peer's public key, our secret key, some additional key material and the given nonce, which must be unique for each distinct message for a key pair.

Returns an encrypted and authenticated message, which is
`nacl.box.overheadLength` longer than the original message.

#### qbox.open(box, nonce, theirPublicKey, mySecretKey, extraKeyMaterial)

Authenticates and decrypts the given box with peer's public key, our secret key, some additional key material, and the given nonce.

Returns the original message, or `false` if authentication fails.

#### qbox.before(theirPublicKey, mySecretKey, extraKeyMaterial)

Returns a precomputed shared key which can be used in `qbox.after` and `qbox.open.after`.

#### qbox.after(message, nonce, sharedKey)

Same as `qbox`, but uses a shared key precomputed with `qbox.before`.

#### qbox.open.after(box, nonce, sharedKey)

Same as `qbox.open`, but uses a shared key precomputed with `qbox.before`.

## Testing

`npm run test`

## License

MIT
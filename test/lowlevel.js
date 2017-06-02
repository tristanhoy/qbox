const nacl = require('tweetnacl')
const qbox = require('../').lowlevel(nacl)
const expect = require('chai').expect

const alice = nacl.box.keyPair()
const bob = nacl.box.keyPair()
const nonce = nacl.randomBytes(nacl.box.nonceLength)
const message = new Uint8Array([ 104, 101, 108, 108, 111 ])// "hello"
const keyMaterial1 = new Uint8Array([ 1, 2, 3, 4 ])
const keyMaterial2 = new Uint8Array([ 5, 6, 7, 8 ])

describe('lowlevel', () => {
  describe('before', () => {
    it('should return the same sharedKey as tweetnacl when no additional keymaterial is provided', () =>
      expect(nacl.verify(
        nacl.box.before(bob.publicKey, alice.secretKey),
        qbox.before(bob.publicKey, alice.secretKey)
      )).to.equal(true)
    )
    it('should return the same sharedKey for both sender and receiver when no additional keymaterial is provided', () =>
      expect(nacl.verify(
        qbox.before(bob.publicKey, alice.secretKey),
        qbox.before(alice.publicKey, bob.secretKey)
      )).to.equal(true)
    )
    it('should accept additional keymaterial as Uint8Array', () =>
      expect(nacl.verify(
        qbox.before(bob.publicKey, alice.secretKey, keyMaterial1),
        qbox.before(alice.publicKey, bob.secretKey, keyMaterial1)
      )).to.equal(true)
    )
    it('should accept additional keymaterial as Uint8Array[]', () =>
      expect(nacl.verify(
        qbox.before(bob.publicKey, alice.secretKey, [ keyMaterial1, keyMaterial2 ]),
        qbox.before(alice.publicKey, bob.secretKey, [ keyMaterial1, keyMaterial2 ])
      )).to.equal(true)
    )
    it('should return the same sharedKey whether additional keymaterial is Uint8Array or Uint8Array[1]', () =>
      expect(nacl.verify(
        qbox.before(bob.publicKey, alice.secretKey, keyMaterial1),
        qbox.before(bob.publicKey, alice.secretKey, [ keyMaterial1 ])
      )).to.equal(true)
    )
  })
  describe('box', () => {
    it('should encrypt identically to tweetnacl when no additional keymaterial is provided', () =>
      expect(nacl.verify(
        nacl.box(message, nonce, bob.publicKey, alice.secretKey),
        qbox(message, nonce, bob.publicKey, alice.secretKey)
      )).to.equal(true)
    )
    it('should encrypt and decrypt correctly when no additional keymaterial is provided', () =>
      expect(nacl.verify(
        qbox.open(qbox(message, nonce, bob.publicKey, alice.secretKey), nonce, alice.publicKey, bob.secretKey),
        message
      )).to.equal(true)
    )
    it('should accept additional keymaterial as Uint8Array', () =>
      expect(nacl.verify(
        qbox.open(qbox(message, nonce, bob.publicKey, alice.secretKey, keyMaterial1), nonce, alice.publicKey, bob.secretKey, keyMaterial1),
        message
      )).to.equal(true)
    )
    it('should accept additional keymaterial as Uint8Array[]', () =>
      expect(nacl.verify(
        qbox.open(qbox(message, nonce, bob.publicKey, alice.secretKey, [ keyMaterial1, keyMaterial2 ]), nonce, alice.publicKey, bob.secretKey, [ keyMaterial1, keyMaterial2 ]),
        message
      )).to.equal(true)
    )
    it('should fail to decrypt if incorrect keymaterial is provided', () =>
      expect(
        qbox.open(qbox(message, nonce, bob.publicKey, alice.secretKey, keyMaterial1), nonce, alice.publicKey, bob.secretKey, keyMaterial2)
      ).to.equal(null)
    )
  })
})

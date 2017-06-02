const nacl = require('tweetnacl')
const ntruBox = require('../').ntru(nacl)
const expect = require('chai').expect

const alice = ntruBox.keyPair()
const bob = ntruBox.keyPair()
const eve = ntruBox.keyPair.sendOnly()
const nonce = nacl.randomBytes(nacl.box.nonceLength)
const message = new Uint8Array([ 104, 101, 108, 108, 111 ])// "hello"

describe('ntruBox', () => {
  describe('before', () => {
    it('should return the same sharedKey for both sender and receiver when full keys are used', () => {
      const { sharedKey, kem } = ntruBox.before(bob.publicKey, alice.secretKey)
      expect(nacl.verify(
        sharedKey,
        ntruBox.open.before(alice.publicKey, bob.secretKey, kem)
      )).to.equal(true)
    })
    it('should return the same sharedKey for both sender and receiver when a sendOnly key is used', () => {
      const { sharedKey, kem } = ntruBox.before(bob.publicKey, eve.secretKey)
      expect(nacl.verify(
        sharedKey,
        ntruBox.open.before(eve.publicKey, bob.secretKey, kem)
      )).to.equal(true)
    })
  })
  describe('box', () => {
    it('should encrypt and decrypt correctly when full keys are used', () => {
      const { box, kem } = ntruBox(message, nonce, bob.publicKey, alice.secretKey)

      expect(nacl.verify(
        ntruBox.open(box, nonce, alice.publicKey, bob.secretKey, kem),
        message
      )).to.equal(true)
    })
    it('should encrypt and decrypt correctly when a sendOnly key is used', () => {
      const { box, kem } = ntruBox(message, nonce, bob.publicKey, eve.secretKey)

      expect(nacl.verify(
        ntruBox.open(box, nonce, eve.publicKey, bob.secretKey, kem),
        message
      )).to.equal(true)
    })
  })
})

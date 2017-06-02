const append = require('./append.js')
const ntru = require('../node_modules/ntru/dist/ntru') // dirty fix

module.exports = (nacl) => {
  const qbox = require('./lowlevel.js')(nacl)

  const ntruBox = function (message, nonce, receiverPublicKey, senderSecretKey) {
    const before = ntruBox.before(receiverPublicKey, senderSecretKey)

    return {
      box: ntruBox.after(message, nonce, before.sharedKey),
      kem: before.kem
    }
  }

  ntruBox.before = (receiverPublicKey, senderSecretKey) => {
    const recieverEccPublicKey = receiverPublicKey.subarray(0, nacl.box.publicKeyLength)
    const receiverNtruPublicKey = receiverPublicKey.subarray(nacl.box.publicKeyLength)
    const senderEccSecretKey = senderSecretKey.subarray(0, nacl.box.secretKeyLength)
    const ntruSharedKey = nacl.randomBytes(ntru.plaintextBytes)

    return {
      sharedKey: qbox.before(recieverEccPublicKey, senderEccSecretKey, ntruSharedKey),
      kem: ntru.encrypt(ntruSharedKey, receiverNtruPublicKey)
    }
  }

  ntruBox.after = qbox.after

  ntruBox.open = (box, nonce, senderPublicKey, receiverSecretKey, kem) => {
    const sharedKey = ntruBox.open.before(senderPublicKey, receiverSecretKey, kem)

    return ntruBox.open.after(box, nonce, sharedKey)
  }

  ntruBox.open.before = function (senderPublicKey, receiverSecretKey, kem) {
    const recieverEccSecretKey = receiverSecretKey.subarray(0, nacl.box.secretKeyLength)
    const receiverNtruSecretKey = receiverSecretKey.subarray(nacl.box.secretKeyLength)
    const senderEccPublicKey = senderPublicKey.subarray(0, nacl.box.publicKeyLength)
    const ntruSharedKey = ntru.decrypt(kem, receiverNtruSecretKey)

    return qbox.before(senderEccPublicKey, recieverEccSecretKey, ntruSharedKey)
  }

  ntruBox.open.after = qbox.open.after

  ntruBox.keyPair = function () {
    const eccKey = nacl.box.keyPair()
    const ntruKey = ntru.keyPair()

    return {
      secretKey: append(eccKey.secretKey, ntruKey.privateKey),
      publicKey: append(eccKey.publicKey, ntruKey.publicKey)
    }
  }

  ntruBox.keyPair.sendOnly = nacl.box.keyPair

  return ntruBox
}

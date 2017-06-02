const append = require('./append.js')

module.exports = (nacl) => {
  const qbox = function (message, nonce, receiverPublicKey, senderSecretKey, extraKeyMaterial) {
    const sharedKey = qbox.before(receiverPublicKey, senderSecretKey, extraKeyMaterial)

    return qbox.after(message, nonce, sharedKey)
  }

  qbox.after = nacl.box.after

  qbox.before = (publicKey, secretKey, additionalKeyMaterial) => {
    let km = nacl.box.before(publicKey, secretKey)

    if (typeof additionalKeyMaterial === 'undefined' || !additionalKeyMaterial) return km

    if (additionalKeyMaterial instanceof Uint8Array) {
      additionalKeyMaterial = [ additionalKeyMaterial ]
    } else if (additionalKeyMaterial[0] instanceof Uint8Array) {
      for (let i = 1; i < additionalKeyMaterial.length; i++) {
        if (!(additionalKeyMaterial[i] instanceof Uint8Array)) throw new TypeError('unexpected type, use Uint8Array or Uint8Array[]')
      }
    } else {
      throw new TypeError('unexpected type, use Uint8Array or Uint8Array[]')
    }

    return nacl.hash(append(km, ...additionalKeyMaterial)).subarray(0, 32)
  }

  qbox.open = (box, nonce, senderPublicKey, receiverSecretKey, extraKeyMaterial) => {
    const sharedKey = qbox.before(senderPublicKey, receiverSecretKey, extraKeyMaterial)

    return qbox.open.after(box, nonce, sharedKey)
  }

  qbox.open.after = nacl.box.open.after

  return qbox
}

module.exports = function () {
  let length = 0
  let pos = 0
  for (let buf of arguments) { length += buf.length }
  const result = new Uint8Array(length)
  for (let buf of arguments) {
    result.set(buf, pos)
    pos += buf.length
  }
  return result
}

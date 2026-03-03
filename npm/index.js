'use strict'

const path = require('path')

function resolveBinary() {
  const { platform, arch } = process

  if (platform === 'darwin') {
    return path.join(__dirname, 'bin', 'Chipkey.app', 'Contents', 'MacOS', 'chipkey')
  }

  if (platform === 'linux') {
    const cpu = arch === 'arm64' ? 'arm64' : 'x64'
    return path.join(__dirname, 'bin', `chipkey-linux-${cpu}`)
  }

  if (platform === 'win32') {
    const cpu = arch === 'arm64' ? 'arm64' : 'x64'
    return path.join(__dirname, 'bin', `chipkey-win32-${cpu}.exe`)
  }

  throw new Error(`chipkey: unsupported platform "${platform}" (${arch})`)
}

module.exports = { resolveBinary }

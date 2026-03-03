#!/usr/bin/env node
'use strict'

const { execFileSync } = require('child_process')
const { resolveBinary } = require('../index.js')

try {
  execFileSync(resolveBinary(), process.argv.slice(2), { stdio: 'inherit' })
} catch (/** @type {any} */ e) {
  process.exit(e.status ?? 1)
}

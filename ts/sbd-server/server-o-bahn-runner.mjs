#!/usr/bin/env node

import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { stdin, exit, platform, pid, kill } from 'node:process'
import nodeCleanup from 'node-cleanup'

const reReady = new RegExp('^.*Ready on http:\/\/(.*)$', 'm')

class Srv {
  #proc
  #addr

  constructor(proc) {
    this.#proc = proc
    this.#addr = null
  }

  static async spawn() {
    const proc = spawn('node', [
      './node_modules/.bin/wrangler',
      'dev',
      '--show-interactive-dev-session',
      'false',
      '--ip',
      '127.0.0.1',
      '--port',
      '0'
    ])

    const out = new Srv(proc)

    const rl = createInterface({
      input: proc.stdout,
    })

    return await new Promise((r, _) => {
      rl.on('line', (line) => {
        //console.log(`stdout:line:${line}`)
        const match = line.match(reReady)
        if (match && match.length > 1 && match[1]) {
          out.#addr = match[1]
          rl.close()
          r(out)
        }
      })
    })
  }

  addr() {
    return this.#addr
  }

  kill() {
    this.#proc.kill('SIGKILL')
  }
}

console.log('CMD/READY')

let _glb_srv = null

nodeCleanup((_code, sig) => {
  if (_glb_srv) {
    _glb_srv.kill()
  }
  kill(pid, sig)
})

const rl = createInterface({
  input: stdin,
})

for await (const line of rl) {
  if (line === 'CMD/START') {
    if (_glb_srv) {
      _glb_srv.kill()
    }
    _glb_srv = await Srv.spawn()
    const addr = _glb_srv.addr()
    console.log(`CMD/START/${addr}`)
  } else {
    console.error('INVALID CMD: ' + line)
    if (_glb_srv) {
      _glb_srv.kill()
    }
    exit(127)
  }
}

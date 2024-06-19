#!/usr/bin/env node

import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { stdin, exit } from 'node:process'

const reReady = new RegExp('^.*Ready on http:\/\/(.*)$', 'm')

class Srv {
  #proc
  #addr

  constructor(proc) {
    this.#proc = proc
    this.#addr = null
  }

  static async spawn() {
    const proc = spawn('npx', [
      'wrangler',
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

  async kill() {
    if (!this.#proc.kill('SIGTERM')) {
      await new Promise((r, _) => {
        setTimeout(r, 1000)
      })
      this.#proc.kill('SIGKILL')
    }
  }
}

console.log('CMD/READY')

let _glb_srv = null

const rl = createInterface({
  input: stdin,
})

for await (const line of rl) {
  if (line === 'CMD/START') {
    if (_glb_srv) {
      await _glb_srv.kill()
    }
    _glb_srv = await Srv.spawn()
    const addr = _glb_srv.addr()
    console.log(`CMD/START/${addr}`)
  } else {
    console.error('INVALID CMD: ' + line)
    exit(127)
  }
}

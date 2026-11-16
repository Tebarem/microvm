// SPDX-License-Identifier: MIT
// The unmodified e2b JS SDK against microvm-sbxd (SANDBOX.md).
//
//   E2B_API_URL=http://127.0.0.1:3917 E2B_SANDBOX_URL=http://127.0.0.1:3917 \
//   E2B_API_KEY=... E2B_DOMAIN=sbx.test NODE_PATH=SDK/node_modules node e2b_js.mjs TEMPLATE [NET_TEMPLATE]
//
// Each check prints ok or FAIL; the exit status is the number of failures.
// Not part of ctest: it needs the SDK (npm install e2b).
import { createRequire } from 'node:module'
import http from 'node:http'
import path from 'node:path'

// ESM ignores NODE_PATH; resolve the SDK through it explicitly.
const require = createRequire(path.join(process.env.NODE_PATH || '.', 'x.js'))
const { Sandbox, CommandExitError, NotFoundError, FileType, FilesystemEventType } = await import(require.resolve('e2b'))

const TEMPLATE = process.argv[2] || 'base'
const NET_TEMPLATE = process.argv[3]
let fails = 0

async function check(name, fn) {
  const t0 = performance.now()
  let ok, detail = ''
  try {
    const r = await fn()
    ok = r === undefined || r === true
    if (!ok) detail = ': ' + JSON.stringify(r)?.slice(0, 200)
  } catch (e) {
    ok = false
    detail = `: ${e?.name}: ${e?.message}`
    if (process.env.VERBOSE) console.error(e)
  }
  const dt = (performance.now() - t0).toFixed(1)
  if (!ok) fails++
  console.log(`  ${(name + ` (${dt} ms)`).padEnd(66)} ${ok ? 'ok' : 'FAIL' + detail}`)
}

// What a client of getHost() does, with the wildcard DNS replaced by the Host header.
function proxiedGet(host, p) {
  const u = new URL(process.env.E2B_SANDBOX_URL)
  return new Promise((resolve, reject) => {
    const req = http.get({ host: u.hostname, port: u.port, path: p, headers: { Host: host }, timeout: 10000 }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve([res.statusCode, Buffer.concat(chunks).toString()]))
    })
    req.on('error', reject)
  })
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

console.log(`e2b JS SDK, template ${TEMPLATE}:`)
let s
await check('Sandbox.create', async () => {
  s = await Sandbox.create(TEMPLATE, { timeoutMs: 120_000, metadata: { suite: 'js' }, envs: { FROM_CREATE: 'yes' } })
  return !!s.sandboxId
})

await check('commands.run: stdout, exit 0', async () => (await s.commands.run('echo hello')).stdout === 'hello\n')
await check('commands.run: a failing command throws, with its output', async () => {
  try {
    await s.commands.run('echo out; echo err >&2; exit 3')
  } catch (e) {
    return e instanceof CommandExitError && e.exitCode === 3 && e.stdout === 'out\n' && e.stderr === 'err\n'
  }
  return 'no error'
})
await check('envs from create and per call, cwd', async () =>
  (await s.commands.run('echo $FROM_CREATE $X; pwd', { envs: { X: '1' }, cwd: '/tmp' })).stdout === 'yes 1\n/tmp\n')
await check('user root', async () => (await s.commands.run('id -u', { user: 'root' })).stdout === '0\n')
await check('onStdout streaming', async () => {
  const got = []
  await s.commands.run('for i in 1 2 3; do echo $i; done', { onStdout: (d) => got.push(d) })
  return got.join('') === '1\n2\n3\n'
})
await check('background, list, kill', async () => {
  const h = await s.commands.run('sleep 30', { background: true })
  const pids = (await s.commands.list()).map((p) => p.pid)
  const killed = await s.commands.kill(h.pid)
  let code = 0
  try { await h.wait() } catch (e) { code = e.exitCode }
  return pids.includes(h.pid) && killed && code !== 0
})
await check('sendStdin', async () => {
  const h = await s.commands.run('head -n 2', { background: true, stdin: true })
  await s.commands.sendStdin(h.pid, 'a\n')
  await s.commands.sendStdin(h.pid, 'b\n')
  return (await h.wait()).stdout === 'a\nb\n'
})
await check('commands.connect', async () => {
  const h = await s.commands.run('sleep 0.3; echo late', { background: true })
  const h2 = await s.commands.connect(h.pid)
  return (await h2.wait()).stdout.endsWith('late\n')
})

// Files.
await check('files.write / read (text)', async () => {
  await s.files.write('/tmp/t/a.txt', 'héllo')
  return (await s.files.read('/tmp/t/a.txt')) === 'héllo'
})
const big = new Uint8Array(3 << 20).map((_, i) => (i * 7919) & 255)
await check('files.write / read 3 MiB (bytes)', async () => {
  await s.files.write('/tmp/t/big.bin', big)
  const back = await s.files.read('/tmp/t/big.bin', { format: 'bytes' })
  return back.length === big.length && Buffer.compare(Buffer.from(back), Buffer.from(big)) === 0
})
await check('files.write (two at once)', async () =>
  (await s.files.write([{ path: '/tmp/t/b.txt', data: 'b' }, { path: '/tmp/t/c.txt', data: 'c' }])).length === 2)
await check('files.list', async () => {
  const names = (await s.files.list('/tmp/t')).map((e) => e.name)
  return ['a.txt', 'big.bin', 'b.txt', 'c.txt'].every((n) => names.includes(n)) || names
})
await check('files.exists', async () => (await s.files.exists('/tmp/t/a.txt')) && !(await s.files.exists('/tmp/t/nope')))
await check('files.getInfo', async () => {
  const i = await s.files.getInfo('/tmp/t/big.bin')
  return i.type === FileType.FILE && i.size === big.length
})
await check('files.makeDir (new, then existing)', async () =>
  (await s.files.makeDir('/tmp/t/d/e')) && !(await s.files.makeDir('/tmp/t/d/e')))
await check('files.rename', async () => (await s.files.rename('/tmp/t/b.txt', '/tmp/t/d/b2.txt')).path === '/tmp/t/d/b2.txt')
await check('files.remove', async () => {
  await s.files.remove('/tmp/t/d')
  return !(await s.files.exists('/tmp/t/d'))
})
await check('reading a missing file throws NotFoundError', async () => {
  try { await s.files.read('/tmp/t/nope') } catch (e) { return e instanceof NotFoundError }
  return 'no error'
})
await check('files.watchDir (recursive)', async () => {
  const evs = []
  const w = await s.files.watchDir('/tmp/t', (e) => evs.push(e), { recursive: true })
  await s.files.write('/tmp/t/new.txt', 'x')
  await s.commands.run('mkdir -p /tmp/t/sub && echo y > /tmp/t/sub/deep.txt')
  for (let i = 0; i < 40 && !['new.txt', 'sub/deep.txt'].every((n) => evs.some((e) => e.name === n)); i++) await sleep(25)
  await w.stop()
  return (['new.txt', 'sub/deep.txt'].every((n) => evs.some((e) => e.name === n)) &&
    evs.some((e) => e.type === FilesystemEventType.CREATE)) || evs.map((e) => [e.name, e.type])
})

// A terminal.
async function ptySize(resize) {
  const out = []
  const h = await s.pty.create({ rows: 24, cols: 80, onData: (d) => out.push(Buffer.from(d)) })
  if (resize) await s.pty.resize(h.pid, { rows: 40, cols: 100 })
  await s.pty.sendInput(h.pid, new TextEncoder().encode('stty size; exit\n'))
  await h.wait()
  const text = Buffer.concat(out).toString()
  return text.includes(resize ? '40 100' : '24 80') || text.slice(-200)
}
await check('pty.create, sendInput, stty size', () => ptySize(false))
await check('pty.resize', () => ptySize(true))

// Ports.
if ((await s.commands.run('command -v python3 || true')).stdout) {
  await check('getHost(8000): a server in the sandbox', async () => {
    await s.files.write('/tmp/www/hi.txt', 'from the sandbox')
    await s.commands.run('cd /tmp/www && exec python3 -m http.server 8000', { background: true })
    const host = s.getHost(8000)
    for (let i = 0; i < 100; i++) {
      try {
        const [st, body] = await proxiedGet(host, '/hi.txt')
        if (st === 200) return body === 'from the sandbox' && host.startsWith(`8000-${s.sandboxId}`)
      } catch {}
      await sleep(50)
    }
    return `no answer from ${host}`
  })
}

// The control plane.
await check('getInfo', async () => {
  const i = await s.getInfo()
  return i.sandboxId === s.sandboxId && i.metadata.suite === 'js' && i.state === 'running' || i
})
await check('Sandbox.list', async () => {
  const items = await Sandbox.list({ query: { metadata: { suite: 'js' } } }).nextItems()
  return items.some((x) => x.sandboxId === s.sandboxId)
})
await check('setTimeout', () => s.setTimeout(300_000))
await check('isRunning', () => s.isRunning())
await check('pause, Sandbox.connect resumes (files, processes)', async () => {
  await s.files.write('/tmp/keep.txt', 'kept')
  const bg = await s.commands.run('sleep 1000', { background: true })
  let t0 = performance.now()
  await s.pause()
  const tp = performance.now() - t0
  const st = (await Sandbox.getInfo(s.sandboxId)).state
  t0 = performance.now()
  s = await Sandbox.connect(s.sandboxId)
  console.log(`    pause ${tp.toFixed(0)} ms, connect-resume ${(performance.now() - t0).toFixed(1)} ms`)
  return st === 'paused' && (await s.files.read('/tmp/keep.txt')) === 'kept' &&
    (await s.commands.list()).some((p) => p.pid === bg.pid)
})
await check('commands after resume', async () => (await s.commands.run('echo again')).stdout === 'again\n')
await check('kill, then getInfo throws', async () => {
  const id = s.sandboxId
  await s.kill()
  try { await Sandbox.getInfo(id) } catch (e) { return e instanceof NotFoundError || e?.name }
  return 'still there'
})
await check('10 concurrent commands', async () => {
  const x = await Sandbox.create(TEMPLATE, { timeoutMs: 60_000 })
  try {
    const rs = await Promise.all([...Array(10).keys()].map((i) => x.commands.run(`echo ${i}`)))
    return rs.every((r, i) => r.stdout === `${i}\n`)
  } finally {
    await x.kill()
  }
})
await check('5 sandboxes, each runs a command', async () => {
  const t0 = performance.now()
  const xs = []
  for (let i = 0; i < 5; i++) xs.push(await Sandbox.create(TEMPLATE, { timeoutMs: 60_000 }))
  console.log(`    ${((performance.now() - t0) / 5).toFixed(1)} ms per Sandbox.create`)
  const ok = (await Promise.all(xs.map((x) => x.commands.run('echo $((1+1))')))).every((r) => r.stdout === '2\n')
  await Promise.all(xs.map((x) => x.kill()))
  return ok
})

if (NET_TEMPLATE) {
  const probe = `python3 -c "import socket; socket.getaddrinfo('debian.org', 443); print('ok')"`
  for (const allow of [true, false]) {
    await check(`allowInternetAccess=${allow}`, async () => {
      const x = await Sandbox.create(NET_TEMPLATE, { timeoutMs: 60_000, allowInternetAccess: allow })
      try {
        let out
        try { out = (await x.commands.run(probe)).stdout } catch { out = 'refused' }
        return out === (allow ? 'ok\n' : 'refused')
      } finally {
        await x.kill()
      }
    })
  }
}

console.log(fails ? 'FAIL' : 'ok', `(${fails} failed)`)
process.exit(Math.min(fails, 100))

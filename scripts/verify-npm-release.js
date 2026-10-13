#!/usr/bin/env node
// Verifies the packed wrapper, not the source directory or npm@latest.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const argv = process.argv.slice(2);
const value = flag => argv[argv.indexOf(flag) + 1];
assert(argv.includes('--run'), '--run must name a fresh owned directory');
const runDir = path.resolve(value('--run'));
assert(!fs.existsSync(runDir), 'Never overwrite an existing verification run');
fs.mkdirSync(runDir, { recursive: true });
const evidence = argv.includes('--evidence') ? path.resolve(value('--evidence')) : path.join(runDir, 'evidence');
fs.mkdirSync(evidence, { recursive: true });
const published = argv.includes('--published');
const transcript = [];
const env = { ...process.env, TOOLTRUST_CACHE_DIR: path.join(runDir, 'bin') };
// npm operations must not use the user's credentials or cache.
for (const name of Object.keys(env)) if (/token|password|secret|npm_config/i.test(name)) delete env[name];
for (const name of ['userconfig', 'globalconfig']) {
  const file = path.join(runDir, name);
  fs.writeFileSync(file, '');
  env['npm_config_' + name] = file;
}
env.npm_config_cache = path.join(runDir, 'npm-cache');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
async function command(label, executable, args, input, extraEnv = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd: root, env: { ...env, ...extraEnv }, shell: executable === 'npm.cmd', stdio: ['pipe', 'pipe', 'pipe'] });
    const entry = { label, executable, args, stdout: '', stderr: '' };
    child.stdout.on('data', d => entry.stdout += d);
    child.stderr.on('data', d => entry.stderr += d);
    child.on('error', reject);
    const timer = setTimeout(() => child.kill(), 180000);
    child.on('close', (code, signal) => {
      clearTimeout(timer); entry.code = code; entry.signal = signal; transcript.push(entry);
      fs.writeFileSync(path.join(evidence, 'release.commands.json'), JSON.stringify(transcript, null, 2));
      resolve(entry);
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input || '');
  });
}
function ok(result) { assert.equal(result.code, 0, result.label + ': ' + result.stderr); return result; }
function sha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
async function download(url, redirects = 0) {
  assert(redirects < 6, 'Too many redirects');
  return await new Promise((resolve, reject) => {
    const request = https.get(url, response => {
      if ([301, 302, 307, 308].includes(response.statusCode)) {
        response.resume(); download(new URL(response.headers.location, url).href, redirects + 1).then(resolve, reject); return;
      }
      if (response.statusCode !== 200) { response.resume(); reject(new Error('Download status ' + response.statusCode)); return; }
      const chunks = []; response.on('data', d => chunks.push(d)); response.on('end', () => resolve(Buffer.concat(chunks))); response.on('error', reject);
    });
    request.setTimeout(60000, () => request.destroy(new Error('Download timed out'))); request.on('error', reject);
  });
}
async function main() {
  const version = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim();
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'npm/package.json')));
  const registry = JSON.parse(fs.readFileSync(path.join(root, 'server.json')));
  assert.equal(pkg.tooltrustBinaryVersion, 'v' + version);
  assert.equal(registry.version, pkg.version);
  assert.equal(registry.packages[0].version, pkg.version);
  if (process.env.GITHUB_REF_TYPE === 'tag') assert.equal(process.env.GITHUB_REF_NAME, 'v' + version);
  const os = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[process.platform];
  const arch = { x64: 'amd64', arm64: 'arm64' }[process.arch];
  assert(os && arch, 'Unsupported verification platform');
  const suffix = os === 'windows' ? '.exe' : '';
  const binaryName = 'tooltrust-mcp_' + os + '_' + arch + suffix;
  const binary = path.join(env.TOOLTRUST_CACHE_DIR, 'v' + version + '_' + binaryName);
  const pack = JSON.parse(ok(await command('npm-pack', npm, ['pack', './npm', '--ignore-scripts', '--json', '--pack-destination', runDir])).stdout)[0];
  assert.deepEqual(pack.files.map(f => f.path).sort(), ['README.md', 'bin/run.js', 'package.json']);
  const tarball = path.join(runDir, pack.filename);
  ok(await command('npm-install-packed', npm, ['install', tarball, '--prefix', path.join(runDir, 'install'), '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', '--offline']));
  const wrapper = path.join(runDir, 'install/node_modules/tooltrust-mcp/bin/run.js');
  assert.equal(ok(await command('npm-version', process.execPath, [wrapper, '--version'])).stdout.trim(), pkg.version);
  assert(!fs.existsSync(binary), '--version must not download a binary');
  fs.mkdirSync(env.TOOLTRUST_CACHE_DIR, { recursive: true });
  if (!published) ok(await command('build-versioned-mcp', 'go', ['build', '-ldflags', '-X main.version=v' + version, '-o', binary, './cmd/tooltrust-mcp']));
  const reqs = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'release-verification', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'tooltrust_scanner_scan', arguments: { tools_json: '{"tools":[]}' } } },
  ].map(x => JSON.stringify(x)).join('\n') + '\n';
  const first = ok(await command('wrapper-rpc', process.execPath, [wrapper], reqs));
  const replies = new Map(first.stdout.trim().split('\n').map(JSON.parse).filter(x => x.id).map(x => [x.id, x]));
  assert(replies.get(2).result.tools.some(t => t.name === 'tooltrust_scanner_scan'));
  assert.equal(replies.get(3).result.isError, true);
  assert(JSON.stringify(replies.get(3)).includes('scan incomplete'));
  assert(ok(await command('binary-version', binary, ['--version'])).stdout.includes('v' + version));
  const digest = sha(binary);
  const warm = ok(await command('wrapper-warm-cache', process.execPath, [wrapper], reqs));
  assert(!warm.stderr.includes('Downloading')); assert.equal(sha(binary), digest);
  if (published) {
    assert(first.stderr.includes('Downloading'), 'Cold cache must download the pinned release');
    const base = 'https://github.com/AgentSafe-AI/tooltrust-scanner/releases/download/v' + version + '/';
    const checksums = (await download(base + 'checksums_' + os + '_' + arch + '.txt')).toString();
    assert(checksums.split('\n').some(line => line.trim().split(/\s+/)[0] === digest && line.trim().split(/\s+/)[1] === binaryName), 'Downloaded MCP binary checksum mismatch');
    const cliName = 'tooltrust-scanner_' + os + '_' + arch + suffix;
    const cli = path.join(runDir, cliName); fs.writeFileSync(cli, await download(base + cliName)); fs.chmodSync(cli, 0o755);
    assert(checksums.split('\n').some(line => line.trim().split(/\s+/)[0] === sha(cli) && line.trim().split(/\s+/)[1] === cliName), 'CLI checksum mismatch');
    assert(ok(await command('released-cli-version', cli, ['version'])).stdout.includes('v' + version));
    const empty = path.join(runDir, 'empty.json'); fs.writeFileSync(empty, '{"tools":[]}');
    assert.notEqual((await command('released-cli-empty', cli, ['scan', '--input', empty])).code, 0);
  }
  // An invalid cached executable must not silently exit successfully.
  fs.renameSync(binary, binary + '.saved'); fs.mkdirSync(binary);
  assert.notEqual((await command('wrapper-spawn-error', process.execPath, [wrapper, '--help'])).code, 0);
  fs.rmdirSync(binary); fs.renameSync(binary + '.saved', binary);
  // Drive an actual OSV 503 through the packaged MCP wrapper.
  const service = http.createServer((req, res) => { req.resume(); res.writeHead(503); res.end('unavailable'); });
  await new Promise(resolve => service.listen(0, '127.0.0.1', resolve));
  try {
    const input = JSON.parse(reqs.trim().split('\n').at(-1));
    input.params.arguments.tools_json = JSON.stringify({ tools: [{ name: 'release_lookup', description: 'Read catalog', inputSchema: { type: 'object' }, metadata: { dependencies: [{ name: 'release-fixture', version: '1.0.0', ecosystem: 'npm' }] } }] });
    const rpc = reqs.trim().split('\n').slice(0, 2).join('\n') + '\n' + JSON.stringify(input) + '\n';
    const failed = ok(await command('wrapper-osv-unavailable', process.execPath, [wrapper], rpc, { TOOLTRUST_OSV_URL: 'http://127.0.0.1:' + service.address().port }));
    const reply = failed.stdout.trim().split('\n').map(JSON.parse).find(x => x.id === 3);
    assert(reply.result.isError && JSON.stringify(reply).includes('scan incomplete'));
  } finally { await new Promise(resolve => service.close(resolve)); }
  fs.writeFileSync(path.join(evidence, 'release.summary.json'), JSON.stringify({ status: 'PASS', scanner: version, npm: pkg.version, published, binary_sha256: digest, tarball_sha256: sha(tarball), tarball, checks: ['version alignment', 'package allowlist', 'packed install', 'MCP initialization/listing', 'empty scan', 'OSV failure', 'warm cache', 'spawn failure', ...(published ? ['cold download', 'asset checksums', 'released CLI'] : [])] }, null, 2));
  console.log('Release verification PASS (' + (published ? 'published assets' : 'local binary') + ')');
}
main().catch(error => { fs.writeFileSync(path.join(evidence, 'release.failure.txt'), error.stack); console.error(error); process.exitCode = 1; });

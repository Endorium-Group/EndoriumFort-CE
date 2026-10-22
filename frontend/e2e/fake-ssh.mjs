// A throwaway SSH server with a toy shell, so the tests can open real SSH
// sessions through the bastion without any real host. Each shell has an id:
//   who    -> "shell-id=<id>"            (tells whether it is the same shell)
//   later  -> "delayed-output" after 2 s (arrives while no browser is attached)
//   exit   -> closes the shell
//   exit-later -> closes the shell after 1 s (while no browser is attached)
import crypto from 'node:crypto';
import ssh2 from 'ssh2';

const { Server } = ssh2;

export function startFakeSsh({ port, user, password }) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });
  let shells = 0;
  const server = new Server({ hostKeys: [privateKey] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.username === user && ctx.password === password) ctx.accept();
      else ctx.reject(['password']);
    });
    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (ok) => ok && ok());
        session.on('window-change', (ok) => ok && ok());
        session.on('shell', (ok) => {
          const stream = ok();
          const id = `${++shells}-${crypto.randomBytes(3).toString('hex')}`;
          stream.write(`toy shell ${id}\r\n$ `);
          let line = '';
          stream.on('data', (data) => {
            for (const ch of data.toString()) {
              if (ch !== '\r' && ch !== '\n') {
                if (ch === '\b' || ch === '\x7f') line = line.slice(0, -1);
                else { line += ch; stream.write(ch); }
                continue;
              }
              const cmd = line.trim();
              line = '';
              stream.write('\r\n');
              if (cmd === 'who') stream.write(`shell-id=${id}\r\n$ `);
              else if (cmd === 'later') setTimeout(() => { try { stream.write('delayed-output\r\n$ '); } catch { /* closed */ } }, 2000);
              else if (cmd === 'exit-later') setTimeout(() => { try { stream.exit(0); stream.end(); } catch { /* closed */ } }, 1000);
              else if (cmd === 'exit') { stream.write('bye\r\n'); stream.exit(0); stream.end(); return; }
              else stream.write(`echo:${cmd}\r\n$ `);
            }
          });
        });
      });
    });
    client.on('error', () => {});
  });
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, '0.0.0.0', () => resolve(() => new Promise((done) => server.close(() => done()))));
  });
}

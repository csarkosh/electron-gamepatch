// Probe: lock -> real Esc (osascript on macOS, PowerShell SendKeys on Windows, goes through
// the window server like a keyboard) -> click every 100 ms until relocked. Reports the gap and
// whether the page saw Esc while locked.
const { app, BrowserWindow, ipcMain } = require('electron');
const { execFile } = require('child_process');
const path = require('path');

const ROUNDS = Number(process.env.ROUNDS || 3);
const results = [];
let win, round = 0, state = 'idle', relockTimer = null, relockStart = 0, relockAttempts = 0;
let sawEscapeWhileLocked = false;

const out = (o) => process.stdout.write(JSON.stringify(o) + '\n');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function click() {
  const [w, h] = win.getContentSize();
  const ev = { x: (w / 2) | 0, y: (h / 2) | 0, button: 'left', clickCount: 1 };
  win.webContents.sendInputEvent({ type: 'mouseDown', ...ev });
  win.webContents.sendInputEvent({ type: 'mouseUp', ...ev });
}
function pressEscape() {
  // A real keystroke through the OS input queue, not sendInputEvent: Chromium's
  // Esc handling for pointer lock runs in the browser process on real key events.
  const onError = (err, so, se) => {
    if (err) { out({ error: 'keystroke-failed', detail: String(se || err) }); app.exit(3); }
  };
  if (process.platform === 'win32') {
    execFile('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{ESC}')"], onError);
  } else {
    execFile('osascript', ['-e', 'tell application "System Events" to key code 53'], onError);
  }
}
function finish(code) {
  const ok = results.length === ROUNDS && results.every((r) => r.attempts === 1 && r.sawEscapeWhileLocked);
  out({ summary: results, rounds: ROUNDS, ok });
  app.exit(code ?? (ok ? 0 : 1));
}
async function runRound() {
  round++; sawEscapeWhileLocked = false; state = 'locking';
  click();
}
ipcMain.on('probe', async (_e, m) => {
  if (m.kind === 'keydown-escape' && m.locked) sawEscapeWhileLocked = true;
  if (m.kind === 'pointerlockchange' && m.locked && state === 'locking') {
    state = 'escaping'; await sleep(400); pressEscape();
  } else if (m.kind === 'pointerlockchange' && !m.locked && state === 'escaping') {
    state = 'relocking'; relockStart = Date.now(); relockAttempts = 0;
    const tick = () => { relockAttempts++; click(); };
    tick(); relockTimer = setInterval(tick, 100);
  } else if (m.kind === 'pointerlockchange' && m.locked && state === 'relocking') {
    clearInterval(relockTimer);
    results.push({ round, relockGapMs: Date.now() - relockStart, attempts: relockAttempts, sawEscapeWhileLocked });
    state = 'escaping2'; await sleep(400); pressEscape();
  } else if (m.kind === 'pointerlockchange' && !m.locked && state === 'escaping2') {
    if (round < ROUNDS) { await sleep(1600); runRound(); } else finish();
  }
});
app.whenReady().then(async () => {
  win = new BrowserWindow({ width: 800, height: 600, webPreferences: { preload: path.join(__dirname, 'preload.js') } });
  await win.loadFile('index.html');
  app.focus({ steal: true }); win.focus();
  await sleep(1200);
  runRound();
});
setTimeout(() => { out({ error: 'timeout', state, results }); finish(2); }, Number(process.env.TIMEOUT_MS || 60000));

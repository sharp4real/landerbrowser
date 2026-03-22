'use strict';
// launch.js — reliably clears ELECTRON_RUN_AS_NODE before starting Electron.
// VS Code's integrated terminal injects ELECTRON_RUN_AS_NODE=1, which makes
// the Electron binary behave like plain Node.js (no window, no app object).
// Deleting it here guarantees Electron always starts in GUI mode.

const { spawn } = require('child_process');
const path = require('path');

const env = Object.assign({}, process.env);
delete env.ELECTRON_RUN_AS_NODE;

// require('electron') returns the path to the electron binary in Node context
const electronBin = require('electron');
const extraArgs = process.argv.slice(2); // e.g. ['--inspect']

const child = spawn(electronBin, ['.'].concat(extraArgs), {
  stdio: 'inherit',
  env,
  cwd: path.resolve(__dirname),
});

child.on('exit', function(code) { process.exit(code || 0); });

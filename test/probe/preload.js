const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('probe', { send: (m) => ipcRenderer.send('probe', m) });

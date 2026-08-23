#  Node.js & Express Integration Guide

This guide explains how to integrate STEALTHWALL into **Node.js (Express.js)** applications.

---

## 1. Installation

```bash
npm install stealthwall
```

---

## 2. Quickstart: 1-Line Plug-and-Play

```javascript
const express = require('express');
const { stealthwall } = require('stealthwall');

const app = express();

//  ONE LINE: Attach StealthWall middleware
app.use(stealthwall());

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Protected by StealthWall' });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

---

## 3. TypeScript Integration

```typescript
import express, { Request, Response } from 'express';
import { stealthwall } from 'stealthwall';

const app = express();

app.use(stealthwall({
  whitelist: ['192.168.1.1', '10.0.0.0/8'],
  excludePaths: ['/health', '/metrics'],
  observeOnly: false,
}));

app.get('/api/users', (req: Request, res: Response) => {
  res.json([{ id: 1, name: 'Alice' }]);
});

app.listen(3000);
```

---

## 4. Connecting to the Python Control-Plane Daemon

By default, the Express middleware evaluates sliding windows locally using `onnxruntime-node`. To connect to a centralized Python control-plane daemon (handling iptables blocks and cluster state), configure `decisionServer`:

```javascript
app.use(stealthwall({
  decisionServer: 'http://127.0.0.1:9377',
  timeoutMs: 50 // Fail-open safety bound
}));
```

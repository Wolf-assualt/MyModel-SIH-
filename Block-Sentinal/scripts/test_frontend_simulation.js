const fs = require('fs');

const appJs = fs.readFileSync('backend/app/static/js/app.js', 'utf8');
const apiJs = fs.readFileSync('backend/app/static/js/api.js', 'utf8');
const graphJs = fs.readFileSync('backend/app/static/js/graph.js', 'utf8');
const indexHtml = fs.readFileSync('backend/app/templates/index.html', 'utf8');

// Basic DOM stub environment
const globalElements = {};

function createMockElement(id, tag = 'div') {
  return {
    id: id,
    tagName: tag.toUpperCase(),
    className: '',
    style: {},
    classList: {
      add: function(c) { this._classes = this._classes || new Set(); this._classes.add(c); },
      remove: function(c) { this._classes = this._classes || new Set(); this._classes.delete(c); },
      toggle: function(c, v) { 
        this._classes = this._classes || new Set();
        if (v === undefined) {
          if (this._classes.has(c)) this._classes.delete(c); else this._classes.add(c);
        } else if (v) this._classes.add(c); else this._classes.delete(c);
      },
      contains: function(c) { return (this._classes || new Set()).has(c); }
    },
    addEventListener: function(evt, handler) {
      this._listeners = this._listeners || {};
      this._listeners[evt] = this._listeners[evt] || [];
      this._listeners[evt].push(handler);
    },
    click: function() {
      if (this._listeners && this._listeners['click']) {
        this._listeners['click'].forEach(h => h({ stopPropagation: () => {}, preventDefault: () => {} }));
      }
    },
    querySelector: function(sel) { return createMockElement('sub-' + sel); },
    querySelectorAll: function(sel) { return [createMockElement('sub1'), createMockElement('sub2')]; },
    getAttribute: function(name) { return 'test-val'; },
    setAttribute: function(name, val) { this[name] = val; },
    appendChild: function(child) { this._children = this._children || []; this._children.push(child); },
    removeChild: function(child) { if (this._children) this._children = this._children.filter(c => c !== child); },
    remove: function() {},
    textContent: '',
    innerHTML: ''
  };
}

global.window = {
  scrollTo: () => {},
  addEventListener: (evt, h) => { if (evt === 'DOMContentLoaded') h(); },
  localStorage: { getItem: () => 'dark', setItem: () => {} },
  setTimeout: (fn, ms) => fn(),
  setInterval: (fn, ms) => {},
  clearInterval: () => {},
  requestAnimationFrame: (fn) => 1,
  cancelAnimationFrame: (id) => {},
  matchMedia: () => ({ matches: false, addEventListener: () => {} }),
  fetch: async () => ({ ok: true, json: async () => ({ success: true, data: { ready: true } }) })
};

global.document = {
  documentElement: createMockElement('html', 'html'),
  getElementById: (id) => {
    if (!globalElements[id]) globalElements[id] = createMockElement(id);
    return globalElements[id];
  },
  querySelector: (sel) => createMockElement('qs-' + sel),
  querySelectorAll: (sel) => [createMockElement('item-1'), createMockElement('item-2')],
  createElement: (tag) => createMockElement('new-' + tag, tag),
  createElementNS: (ns, tag) => createMockElement('ns-' + tag, tag),
  addEventListener: (evt, h) => { if (evt === 'DOMContentLoaded') h(); }
};

global.localStorage = global.window.localStorage;
global.fetch = global.window.fetch;
global.FormData = class { constructor() { this.entries = {}; } append(k, v) { this.entries[k] = v; } };

try {
  eval(apiJs);
  console.log('[PASS] api.js evaluated without errors.');
  eval(graphJs);
  console.log('[PASS] graph.js evaluated without errors.');
  eval(appJs);
  console.log('[PASS] app.js evaluated without errors and DOM events initialized.');

  // Test Mode switching
  document.getElementById('tab-mode-upload').click();
  console.log('[PASS] Click tab-mode-upload handled cleanly.');
  document.getElementById('tab-mode-demo').click();
  console.log('[PASS] Click tab-mode-demo handled cleanly.');

  // Test Theme toggle
  document.getElementById('btn-theme-toggle').click();
  console.log('[PASS] Click btn-theme-toggle handled cleanly.');

  // Test Launch Button
  document.getElementById('btn-launch-mission').click();
  console.log('[PASS] Click btn-launch-mission handled cleanly.');

  // Test Drawer Open / Close
  document.getElementById('btn-open-drawer').click();
  console.log('[PASS] Click btn-open-drawer handled cleanly.');
  document.getElementById('btn-close-drawer').click();
  console.log('[PASS] Click btn-close-drawer handled cleanly.');

  console.log('\n======================================================');
  console.log('ALL FRONTEND INTERACTIVE CONTROLS & EVENT HANDLERS PASS');
  console.log('======================================================');
} catch (err) {
  console.error('[FAIL] Runtime Error during JS Evaluation:', err);
  process.exit(1);
}

(function () {
  'use strict';
  var root = document.documentElement;
  var btn = document.getElementById('theme');
  var label = document.getElementById('theme-label');

  function paint() {
    label.textContent = root.dataset.theme === 'light' ? 'Dark theme' : 'Light theme';
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = root.dataset.theme === 'light' ? '#eef2f6' : '#141c27';
  }
  btn.addEventListener('click', function () {
    var next = root.dataset.theme === 'light' ? 'dark' : 'light';
    root.dataset.theme = next;
    try { localStorage.setItem('ntb-site-theme', next); } catch (e) {}
    paint();
  });
  paint();

  // screenshot tabs
  var tabs = document.querySelectorAll('.tabs button');
  var panes = document.querySelectorAll('.shot');
  tabs.forEach(function (t) {
    t.addEventListener('click', function () {
      tabs.forEach(function (o) { o.setAttribute('aria-selected', String(o === t)); });
      panes.forEach(function (p) { p.hidden = p.dataset.pane !== t.dataset.shot; });
    });
  });
})();

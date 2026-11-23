// Small effects: a glow that follows the pointer, and the home terminal
// typing its commands. Both are skipped when the visitor asks for reduced
// motion. The terminal's lines are hidden by CSS (the "fx" class set in the
// page head) and shown here one by one; CSS shows them anyway after 4 s.
(function () {
  var still = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (still) return;

  if (matchMedia('(hover: hover)').matches) {
    var root = document.documentElement, raf = 0, x = 0, y = 0;
    window.addEventListener('pointermove', function (e) {
      x = e.clientX; y = e.clientY;
      if (raf) return;
      raf = requestAnimationFrame(function () {
        raf = 0;
        root.style.setProperty('--mx', x + 'px');
        root.style.setProperty('--my', y + 'px');
        root.classList.add('glow-on');
      });
    }, { passive: true });
  }

  var body = document.querySelector('.term-body');
  if (!body) return;
  var steps = Array.prototype.slice.call(body.children);

  var i = 0;
  function next() {
    if (i >= steps.length) return;
    var el = steps[i++];
    var cmd = el.querySelector('[data-type]');
    el.classList.add('shown');
    if (!cmd) { setTimeout(next, 160); return; }
    var text = cmd.textContent, n = 0;
    cmd.textContent = '';
    (function type() {
      cmd.textContent = text.slice(0, ++n);
      if (n < text.length) setTimeout(type, 38 + Math.random() * 40);
      else setTimeout(next, 220);
    })();
  }
  next();
})();

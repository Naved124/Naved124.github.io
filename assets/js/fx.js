// The home terminal typing its commands, skipped when the visitor asks for
// reduced motion. The terminal's lines are hidden by CSS (the "fx" class set in the
// page head) and shown here one by one; CSS shows them anyway after 4 s.
(function () {
  var still = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (still) return;

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

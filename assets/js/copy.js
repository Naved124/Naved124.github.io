// Adds a "copy" button to every highlighted code block.
document.querySelectorAll(".highlight").forEach((block) => {
  const code = block.querySelector("code");
  if (!code || !navigator.clipboard) return;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copy-btn";
  btn.textContent = "copy";
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code.innerText.replace(/\n$/, ""));
      btn.textContent = "copied";
    } catch {
      btn.textContent = "failed";
    }
    setTimeout(() => (btn.textContent = "copy"), 1500);
  });
  block.appendChild(btn);
});

# naved // security notes

My security blog: writeups for retired HTB/THM boxes, notes on what I'm learning, and bug bounty updates.
Built with [Hugo](https://gohugo.io) and published to GitHub Pages by a GitHub Actions workflow on every push to `main`.

## Layout

```
content/
  writeups/   retired HTB/THM boxes
  notes/      concepts, PortSwigger learnings, cloud security
  bugs/       disclosed bug bounty findings and updates
  about.md
archetypes/   templates for new posts (one per section)
layouts/      the site's own theme (no external theme to update)
assets/css/   main.css (look) + syntax.css (code colours)
.github/workflows/hugo.yml   build + deploy
```

## Write a post

```bash
hugo new content writeups/<box-name>.md     # or notes/<topic>.md, bugs/<title>.md
hugo server -D                               # preview at http://localhost:1313 (includes drafts)
```

Every new post starts as `draft: true`. When it's ready, set `draft: false`, commit and push. The site rebuilds in about a minute.

Put screenshots next to the post by making it a folder instead of a file:

```
content/writeups/<box-name>/index.md
content/writeups/<box-name>/nmap.png      →  ![nmap output](nmap.png)
```

## Publishing rules (enforced by the build)

- **Writeups:** only for **retired** machines. A non-draft writeup without `retired: true` makes the build fail, so it can't go live by accident.
- **Bugs:** only findings the program **disclosed or allowed you to share**. A non-draft bug post without `disclosed: true` fails the build.
- Be honest in `solved:` (solo / partial-help / writeup-assisted). It's what makes the rest believable.
- Never paste real credentials, flags for active content, or anything from loot that belongs to someone else.

## Set up (once)

1. Create a **public** repo named `Naved124.github.io` on GitHub (that name gives the site the URL `https://naved124.github.io/`).
2. Push this folder to it:
   ```bash
   git init -b main
   git add .
   git commit -m "Initial site"
   git remote add origin git@github.com:Naved124/Naved124.github.io.git
   git push -u origin main
   ```
3. In the repo: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
4. Check the **Actions** tab. When the run is green, the site is live.

If you use a different repo name, it still works — the site just lives at `https://naved124.github.io/<repo-name>/`.

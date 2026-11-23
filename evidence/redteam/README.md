# Week 17 attack evidence

Each JSON file is one payload in one mode: every run's report, rendered PR comment, model
replies, and a SHA-256 hash and length for each request. `cpu.txt` and `ollama-backend.txt`
name the runner CPU and the Ollama CPU library.

- `after-fix/`: the `redteam` workflow on `main` at `78f07c8`, run
  [45121996341](https://github.com/Keniolax/codeguardian/actions/runs/45121996341).
- `ablation/`: the `ablation` workflow on `main` at `78f07c8`, run
  [45122025148](https://github.com/Keniolax/codeguardian/actions/runs/45122025148).
- `before-fix/`: the reviewer as shipped at `97ab03c`, run
  [45111923997](https://github.com/Keniolax/codeguardian/actions/runs/45111923997). This run
  scored A3 on the posted canary only; its `lookup` field is empty in hardened mode.

Summarise a folder with `PYTHONPATH=src:. python -m redteam.assess <folder>/qwen2.5-1.5b`.

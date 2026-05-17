# PocketSOC Demo Path

Minimal, realistic demo flow:

```bash
pocketsoc config init
pocketsoc scan run --profile standard
pocketsoc scan dashboard
pocketsoc scan alerts --table
pocketsoc report md --format executive
```

Optional API demo:

```bash
pocketsoc api serve --host 127.0.0.1 --port 8787
curl -s http://127.0.0.1:8787/health
```

This path is defensive-only and local-first.

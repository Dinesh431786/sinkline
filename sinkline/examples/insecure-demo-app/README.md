# Insecure demo app (INTENTIONALLY VULNERABLE)

A tiny, realistic 'analytics service' used to demonstrate Sinkline. Every file
looks normal in isolation, yet together they hide a cross-file credential leak,
a logic bomb in the rate-limiter, an obfuscated plugin loader, an
import-correlated AWS key, an install hook, and a typosquatted dependency.

**Do not run this.** It exists only as a scan target:

```bash
python ../../cli.py scan .
```

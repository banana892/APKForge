# AI explanations (optional)

`apkforge explain` and the workbench's **Explain** button ask an AI model to describe a
result in plain language: what it says overall, which findings matter most and why, what
the analysis could not establish, and what to check next.

APKForge stays local-first. Nothing is sent unless you configure a provider **and** ask
for an explanation. Then only the structured result is sent, never the APK.

## What is sent

| Result | Sent |
|--------|------|
| `analyze` | Package identity, statuses, summaries, warnings, errors and limitations. Each security finding (id, title, severity, confidence, category, description, assessment, limitations) with its first 5 evidence items. |
| `diff` | Identities, summary, warnings, errors and limitations. The flat observation list, up to 500 items. |
| `verify` | The verification matrix, requested/expected/actual/unexpected/unknown changes (up to 500 each), statements, security diff, baseline and toolchain. |

- Results above 400,000 characters after these caps are refused rather than cut.
- Every cap that removed something is reported (`not sent: ...`), to you and to the model.
- Evidence can include strings, file names and URLs taken from the APK.
  - If the APK itself is confidential, use a local model (see below).
- The prompt tells the model to treat the result as untrusted data, because an APK's
  author controls text inside it.
  - The answer is advisory text only and cannot change anything.

## Configuration

Keys come only from the environment. APKForge never writes them to disk, job files or
output.

**Claude** (needs the `ai` extra: `pip install 'apkforge[ai]'`):

```bash
export ANTHROPIC_API_KEY=...            # or an `ant auth login` profile
export APKFORGE_AI_MODEL=claude-opus-5-5   # optional; this is the default
```

With the default model, a request declined by safety classifiers is retried
server-side on a fallback model (`fallbacks: "default"`).

**Any OpenAI-compatible endpoint** (OpenAI, Gemini, Mistral, Groq, OpenRouter, or a local
Ollama or LM Studio):

```bash
export APKFORGE_AI_BASE_URL=https://api.openai.com/v1   # or http://127.0.0.1:11434/v1 for Ollama
export APKFORGE_AI_MODEL=gpt-4.1
export APKFORGE_AI_API_KEY=...          # omit for a local server without auth
```

`APKFORGE_AI_PROVIDER` (`anthropic` | `openai-compatible`) picks one when both are set.
Without it:
- `anthropic` is used when `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set.
- Otherwise `openai-compatible` is used when `APKFORGE_AI_BASE_URL` is set.

## CLI

```bash
apkforge analyze app.apk --json -o analyze.json
apkforge explain analyze.json                  # text; provider and caps on stderr
apkforge explain analyze.json --json           # {provider, model, host, kind, text, omitted, ...}
apkforge explain diff.json --provider openai-compatible --model llama3
```

`RESULT.json` can be:
- the output of `analyze`, `diff` or `verify --json`;
- a job saved with **Download JSON** in the workbench.

Exit codes:
- 2: nothing is configured, or the file cannot be read.
- 1: the provider failed or declined.

## Workbench

Start `apkforge gui` with the variables above set.

A finished Analyze, Diff or Verify result then shows an **Explain** button, with the
provider, model and host it will send to. The explanation runs as a job: it is kept with
the others and can be downloaded. `GET /api/ai` reports the configuration; it never
returns the key.

## Limits

- Explanations are generated text. They can be wrong or miss things; the result itself is
  the record.
- Static analysis cannot prove an APK safe or malicious, and the prompt forbids claiming
  either.
- Small local models follow the requested structure less reliably than large hosted ones.

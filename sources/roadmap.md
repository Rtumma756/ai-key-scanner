# aiscan — source roadmap: not implemented (yet)

Sources ranked by yield that are **not** live-scanned in this prototype,
with the exact reason and what each would need. Nothing here is behind a
paywall the prototype is willing to cross: aiscan runs entirely on free
public access. A source that only works usefully behind a paid key stays
documented here until a free path exists.

## CI build logs

- **What it would scan:** public build logs (GitHub Actions, GitLab CI,
  Travis, CircleCI) that echo environment variables or print `.env`
  contents. A known leak surface: steps like `run: env` or a crash
  reporter dumping the environment.
- **Why not implemented:** there is no single "list all public build
  logs" feed. Each log needs a target repo + workflow + run ID, i.e. a
  target list the user supplies, plus per-repo read access (public repos
  are readable with a free GitHub token, but enumerating *which* repos
  to check is the hard part).
- **What it would need:** a target list (org/repo), a free GitHub token,
  and the Actions API (`/repos/{owner}/{repo}/actions/runs` then
  `/actions/jobs/{job_id}/logs`). Bounded the same way as the GitHub
  source: one repo at a time, logs capped by size.
- **Stub:** `sources/ci_logs.py` — `CILogsSource(repo, token, max_runs)`.

## Misconfigured cloud storage (public S3 buckets, open servers)

- **What it would scan:** public S3 buckets and open HTTP servers
  exposing `.env`, `config.json`, and credential files.
- **Why not implemented:** finding buckets requires enumeration
  (guessing bucket names, search engines), and scanning arbitrary
  buckets at scale is a grey area — the data is public, but the
  prototype's rule is to scan sources the user points it at, not to
  enumerate the internet for targets.
- **What it would need:** a target bucket/host list supplied by the user
  (e.g. buckets belonging to their org, or a public bucket index),
  anonymous HTTP GETs, and the same size caps as the other sources.
- **Stub:** `sources/s3.py` — `S3Source(targets, max_objects)`.

## FOFA / Shodan / Censys (asset search engines)

- **What they would scan:** internet-connected assets exposing config
  files, `.env` endpoints, and credentials — the entry point used by
  the key-harvesting operations documented in the research notes.
- **Why not implemented:** all three require a **paid API key** for
  anything beyond a token free tier (FOFA free tier is a handful of
  queries; Shodan's free tier is essentially unusable for search;
  Censys search is paid). aiscan's hard constraint is free tiers only.
- **What it would need:** a paid FOFA/Shodan/Censys API key and a query
  (e.g. FOFA `body=".env"` or Shodan `http.title` filters), plus the
  same fetch-and-scan pipeline as the other sources.
- **Stub:** `sources/asset_search.py` —
  `AssetSearchSource(provider, api_key, query, max_hosts)`.

## Kaggle / Google Colab notebooks

- **What they would scan:** public notebooks with inline API keys.
- **Why not implemented:** Kaggle needs a (free) API token and Colab
  needs Google auth; neither has a public, unauthenticated search feed
  for notebook contents. The GitHub `.ipynb` preset
  (`scan internet --preset notebook`) covers the public, unauthenticated
  path.
- **What it would need:** a free Kaggle API token
  (`kaggle notebooks list --search ...` + download) or Colab sharing
  links supplied by the user.
- **Stub:** `sources/notebooks.py` — `KaggleSource(token, query)`.

## Pastebin PRO (keyword search)

- **What it would add:** keyword search over pastes (the free
  `PastebinSource` only samples the recent-public archive listing).
- **Why not implemented:** Pastebin's search/scraping API requires a
  paid PRO key. Free form is implemented in `sources/pastebin.py`.

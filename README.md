# agent-traffic for PHP

Tell AI agents, AI crawlers, search crawlers and bots apart from people.

A dependency-free PHP 8.2+ port of [Mintlify's agent-traffic](https://github.com/mintlify/agent-traffic), including its curated dataset, request classification, explanation strings, and operator IP verification.

## Installation

Once published on Packagist:

```sh
composer require 0x15f/agent-traffic
```

## Usage

```php
use AgentTraffic\AgentTraffic;

$result = AgentTraffic::classify([
    'userAgent' => 'Claude-User (claude-code/2.1.308; +https://support.anthropic.com/)',
]);
// category: agent, kind: coding, name: Claude Code, version: 2.1.308

$result = AgentTraffic::classify([
    'headers' => getallheaders(),
    'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
], [
    'ipRanges' => $cachedRanges,
    'headersComplete' => true,
]);
```

Use your framework's trusted-proxy configuration to obtain the real client IP behind a proxy. Only set `headersComplete` when browser headers reach the application intact over HTTPS.

Load and cache operator ranges outside the request path, refreshing about daily:

```php
$ranges = AgentTraffic::loadIpRanges();
// Persist $ranges in your application cache, then pass it as ipRanges.
```

The default downloader uses PHP HTTPS streams (`allow_url_fopen` and a working CA store), a ten-second timeout per source, and sequential downloads. An optional callback receives each URL and returns decoded JSON or a JSON string, so an existing HTTP client can be used. Failed sources are skipped; download failure never establishes impersonation.

## API

`AgentTraffic::classify(array $input, array $options = []): array`

| Input | Description |
| --- | --- |
| `userAgent` | Optional string; otherwise read from headers |
| `headers` | Array with case-insensitive names and string or string-array values |
| `ip` | Optional real client IP; IPv4 ports, bracketed IPv6 and IPv4-mapped IPv6 are supported |

| Option | Default | Description |
| --- | --- | --- |
| `ipRanges` | `[]` | URL-keyed range files from `loadIpRanges()` |
| `headersComplete` | `false` | Enable browser header consistency checks |
| `maxRangeAgeDays` | `180` | Older files can verify matches but cannot establish impersonation |
| `now` | Current time | `DateTimeInterface`, Unix timestamp or date string for deterministic checks |

Results contain `category`, `verified`, `confidence` and `reasons`, plus `kind`, `id`, `name`, `operator` and `version` when known. Optional fields are omitted. `verified` is `true` for a published IP match, `false` for impersonation, and `null` when unverified. Signature-Agent fingerprints identify claims; cryptographic signatures are not verified.

| Category | Meaning |
| --- | --- |
| `agent` | AI product fetching for a person |
| `ai-crawler` | AI company collecting pages ahead of time |
| `crawler` | Search engine |
| `bot` | Other automation, HTTP client, fake browser or impersonator |
| `human` | Consistent browser identity |
| `unknown` | No user agent or headers |

Classification checks known identities first, then markdown preferences, generic clients, browser consistency and fallbacks. Agents running on user machines are never IP-verified. Some agents are invisible at the HTTP level, and shared identities cannot distinguish every product. See [GUIDELINES.md](GUIDELINES.md) for upstream rationale.

Additional static methods:

- `prefersMarkdown(string $accept): bool`
- `agents()`, `httpClients()`, `headers()`: the datasets as arrays
- `userAgents()`: raw regular-expression strings grouped by category
- `patterns()`: category PCRE strings for `preg_match($patterns['agent'], $ua)`
- `loadIpRanges(?callable $fetch = null): array`

The datasets are also shipped as JSON in `data/`. `AgentTraffic\Ip` exposes `normalize()`, `inCidr()` and `parseRangeFile()`. Invalid CIDRs are ignored safely.

## Development

```sh
composer install
composer test
composer lint
composer validate --strict
```

Tests include frozen results from the upstream test suite, every example's category pattern, IP edge cases and failed range downloads. CI runs PHP 8.2–8.5.

## Publishing

Submit `https://github.com/0x15f/php-agent-traffic` to Packagist under `0x15f/agent-traffic`, enable its GitHub update hook, then tag releases with semantic versions (for example `v0.1.0`). Composer derives versions from Git tags; no version field is needed in composer.json.

## Attribution

Port and datasets based on Mintlify agent-traffic at commit `ee1bc00a8c11086c5ddd853f871b8434f8531d0c`. `tests/fixtures.json` records classification calls and expected results from that revision's passing test suite. Dataset updates should preserve order and rerun parity checks. The original MIT copyright notice is retained in [LICENSE](LICENSE).

<?php

declare(strict_types=1);

namespace AgentTraffic;

final class AgentTraffic
{
    private static array $data = [];

    public static function agents(): array
    {
        return self::dataset('agents');
    }

    public static function httpClients(): array
    {
        return self::dataset('http-clients');
    }

    public static function headers(): array
    {
        return self::dataset('headers');
    }

    private static function dataset(string $name): array
    {
        return self::$data[$name] ??= json_decode(file_get_contents(__DIR__."/../data/$name.json"), true, 512, JSON_THROW_ON_ERROR);
    }

    public static function regex(string $pattern): string
    {
        return '~'.str_replace('~', '\\~', $pattern).'~i';
    }

    public static function userAgents(): array
    {
        $out = array_fill_keys(['agent', 'ai-crawler', 'crawler', 'bot'], []);
        foreach (self::agents() as $a) {
            array_push($out[$a['category']], ...$a['userAgents']);
        }
        foreach (self::httpClients() as $c) {
            $out['bot'][] = $c['userAgent'];
        }

        return $out;
    }

    public static function patterns(): array
    {
        return array_map(fn ($patterns) => self::regex(implode('|', array_map(fn ($p) => '(?:'.preg_replace('/\(\?<\w+>/', '(?:', $p).')', $patterns))), self::userAgents());
    }

    private static function ranksAboveHtml(string $accept, array $types): bool
    {
        $ranked = [];
        foreach (explode(',', strtolower($accept)) as $i => $part) {
            $params = explode(';', trim($part));
            $type = trim(array_shift($params));
            $q = 1.0;
            foreach ($params as $param) {
                if (str_starts_with(trim($param), 'q=')) {
                    $raw = substr(trim($param), 2);
                    $q = is_numeric($raw) ? (float) $raw : ($raw === '' ? 0.0 : 1.0);
                    break;
                }
            }
            if ($q > 0) {
                $ranked[] = compact('type', 'q', 'i');
            }
        }
        usort($ranked, fn ($a, $b) => ($b['q'] <=> $a['q']) ?: ($a['i'] <=> $b['i']));
        foreach ($ranked as $r) {
            if (in_array($r['type'], $types, true)) {
                return true;
            }
            if ($r['type'] === 'text/html') {
                return false;
            }
        }

        return false;
    }

    public static function prefersMarkdown(string $accept): bool
    {
        return self::ranksAboveHtml($accept, ['text/markdown', 'text/x-markdown']);
    }

    private static function normalizeAccept(string $value): string
    {
        return trim(preg_replace('/\s*([,;=])\s*/', '$1', strtolower($value)));
    }

    private static function result(string $category, string $confidence, string $reason, ?string $kind = null): array
    {
        $r = ['category' => $category, 'verified' => null, 'confidence' => $confidence, 'reasons' => [$reason]];
        if ($kind !== null) {
            $r['kind'] = $kind;
        }

        return $r;
    }

    public static function classify(array $input, array $options = []): array
    {
        if (isset($options['now'])) {
            $now = $options['now'];
            $timestamp = $now instanceof \DateTimeInterface
                ? $now->getTimestamp()
                : (is_int($now) ? $now : (is_string($now) ? strtotime($now) : false));
            if ($timestamp === false) {
                throw new \InvalidArgumentException('now must be a DateTimeInterface, Unix timestamp or valid date string');
            }
            $options['now'] = $timestamp;
        }

        $h = [];
        foreach ($input['headers'] ?? [] as $key => $value) {
            if ($value !== null) {
                $h[strtolower($key)] = is_array($value) ? implode(', ', $value) : $value;
            }
        }
        $ua = trim($input['userAgent'] ?? $h['user-agent'] ?? '');
        foreach (self::agents() as $a) {
            foreach ($a['userAgents'] as $p) {
                if (preg_match(self::regex($p), $ua, $m)) {
                    return self::fromAgent($a, "user agent matches {$a['name']}", $m['version'] ?? null, false, $input['ip'] ?? null, $options);
                }
            }
        }
        if (! empty($h['accept'])) {
            foreach (self::agents() as $a) {
                foreach ($a['accept'] ?? [] as $accept) {
                    if (self::normalizeAccept($accept) === self::normalizeAccept($h['accept'])) {
                        return self::fromAgent($a, "Accept header matches {$a['name']}'s fingerprint", null, false, $input['ip'] ?? null, $options);
                    }
                }
            }
        }
        if (! empty($h['signature']) && ! empty($h['signature-input']) && ! empty($h['signature-agent'])) {
            $value = $h['signature-agent'];
            $host = preg_match('~https?://([^/"\s]+)~i', $value, $m) ? strtolower($m[1]) : strtolower(trim(str_replace('"', '', preg_replace('/^[\w-]+=/', '', $value))));
            foreach (self::agents() as $a) {
                if (in_array($host, $a['signatureAgent'] ?? [], true)) {
                    return self::fromAgent($a, "signed request names $host in Signature-Agent; the signature itself is not verified", null, true, $input['ip'] ?? null, $options);
                }
            }
        }
        if (! empty($h['accept']) && self::prefersMarkdown($h['accept'])) {
            return self::result('agent', 'medium', 'Accept header prefers markdown over HTML, which browsers never do', 'unidentified');
        }
        foreach (self::httpClients() as $c) {
            if (preg_match(self::regex($c['userAgent']), $ua)) {
                $r = self::result('bot', 'medium', "user agent is {$c['name']}", $c['kind']);
                $r['name'] = $c['name'];

                return $r;
            }
        }
        if (self::isBrowser($ua)) {
            return self::fromBrowser($ua, $h, $options);
        }
        if ($ua === '' && $h === []) {
            return self::result('unknown', 'low', 'no user agent or headers to classify');
        }

        return self::result('bot', 'low', $ua === '' ? 'request has no user agent, which browsers always send' : 'user agent is not a browser and matches no known agent, crawler or client', 'unidentified');
    }

    private static function fromAgent(array $a, string $reason, ?string $version, bool $weak, ?string $rawIp, array $opts): array
    {
        $base = self::result($a['category'], $weak ? 'low' : 'medium', $reason, $a['kind']);
        foreach (['id', 'name', 'operator'] as $k) {
            $base[$k] = $a[$k];
        }
        if ($version !== null) {
            $base['version'] = $version;
        }
        if ($a['runsOn'] === 'user') {
            $base['reasons'][] = "{$a['name']} runs on the user's machine, so IP verification does not apply";

            return $base;
        }
        $ip = $rawIp === null ? null : Ip::normalize($rawIp);
        if ($rawIp !== null && $ip === null) {
            $base['reasons'][] = "IP \"$rawIp\" is not a single valid address, so it was not checked";

            return $base;
        }
        $files = [];
        foreach ($a['verify']['ipRanges'] ?? [] as $url) {
            if (! empty($opts['ipRanges'][$url]['cidrs'])) {
                $files[] = $opts['ipRanges'][$url];
            }
        }
        if ($ip === null || $files === []) {
            return $base;
        }
        foreach ($files as $file) {
            foreach ($file['cidrs'] as $cidr) {
                if (Ip::inCidr($ip, $cidr)) {
                    $base['verified'] = true;
                    $base['confidence'] = 'high';
                    $base['reasons'][] = "$ip is in {$a['operator']}'s published ranges";

                    return $base;
                }
            }
        }
        $now = $opts['now'] ?? new \DateTimeImmutable;
        $now = $now instanceof \DateTimeInterface ? $now->getTimestamp() : (is_int($now) ? $now : strtotime($now));
        $maxAge = $opts['maxRangeAgeDays'] ?? 180;
        foreach ($files as $file) {
            $created = isset($file['createdAt']) ? strtotime($file['createdAt']) : false;
            if ($created !== false && ($now - $created) / 86400 <= $maxAge) {
                $r = self::result('bot', 'high', "claims to be {$a['name']} but $ip is outside {$a['operator']}'s published ranges", 'impersonator');
                $r['verified'] = false;

                return $r;
            }
        }
        $base['reasons'][] = "{$a['operator']}'s range file is older than $maxAge days, so a mismatch is not treated as spoofing";

        return $base;
    }

    private static function isBrowser(string $ua): bool
    {
        if (preg_match('~^(Lynx|ELinks|Links|w3m)/~', $ua)) {
            return true;
        }
        if (! preg_match('~^Mozilla/[4-6]\.0 \(|^Opera/\d~', $ua) || ! preg_match('~\(KHTML,? ?like Gecko|KHTML/[\d.]+ \(like Gecko|Gecko/\d|\) like Gecko|Trident/\d|MSIE \d|Presto/\d|Chromium/\d~', $ua)) {
            return false;
        }
        if (preg_match('~(?:[a-z0-9-]|\b)[Bb]ot(?:\b|/)~', $ua) || preg_match('~[\w.+-]+@[\w-]+(\.[\w-]+)*\.[a-z]{2,}~i', $ua) || preg_match('~crawl|spider|scrap|headless|https?://|\+http|(?:^|[^a-z])(?:archive|observ|monitor|check(?:er)?\b|preview|verif|render|insight|console|transcod|scanner|synthetic)|lighthouse|selenium|cypress|webdriver|\bsplash\b|gomezagent|rigor|speedcurve|\bptst\b|dareboost|dejaclick|favicon|siteimprove|onetrust|datanyze|feeder\.co|rss\b|weblight|duplexweb|ips-agent~i', $ua)) {
            return false;
        }

        return ! str_contains($ua, 'compatible;') || preg_match('~MSIE|Trident|Konqueror~', $ua) === 1;
    }

    private static function fromBrowser(string $ua, array $h, array $opts): array
    {
        $fake = fn ($r, $c) => self::result('bot', $c, $r, 'fake-browser');
        if (! empty($h['accept']) && self::ranksAboveHtml($h['accept'], ['text/plain'])) {
            return $fake('Accept header ranks text/plain above HTML, which browsers never do', 'low');
        }
        if (str_contains($h['accept'] ?? '', 'application/metalink')) {
            return $fake('Accept header asks for metalink, which download tools send and browsers do not', 'medium');
        }
        if (empty($opts['headersComplete'])) {
            return self::result('human', 'low', 'browser user agent; headers not checked');
        }
        if (! empty($h['sec-ch-ua']) && ! str_contains($ua, 'Chrome/')) {
            return $fake('sec-ch-ua sent with a non-Chromium user agent', 'high');
        }
        $metadata = false;
        foreach (['Firefox' => 90, 'Chrome' => 80, 'Version' => 17] as $browser => $minimum) {
            if (preg_match('~'.$browser.'/(\d+)~', $ua, $m) && ($browser !== 'Version' || preg_match('~Version/[\d.]+.*Safari/~', $ua))) {
                $metadata = (int) $m[1] >= $minimum;
                break;
            }
        }
        if (empty($h['sec-fetch-mode']) && $metadata) {
            return $fake('browser user agent without sec-fetch-* headers', 'medium');
        }
        if (empty($h['accept-language'])) {
            return $fake('browser user agent without Accept-Language', 'low');
        }

        return self::result('human', 'medium', 'browser user agent with consistent browser headers');
    }

    /** The fetch callback receives a URL and returns a decoded JSON array or JSON string. Failed sources are skipped. */
    public static function loadIpRanges(?callable $fetch = null): array
    {
        $fetch ??= static function (string $url): string {
            $body = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 10, 'follow_location' => 0, 'user_agent' => 'php-agent-traffic']]));
            if ($body === false) {
                throw new \RuntimeException("Cannot fetch $url");
            }

            return $body;
        };
        $urls = [];
        foreach (self::agents() as $a) {
            foreach ($a['verify']['ipRanges'] ?? [] as $url) {
                $urls[$url] = true;
            }
        }
        $out = [];
        foreach (array_keys($urls) as $url) {
            try {
                $body = $fetch($url);
                $body = is_string($body) ? json_decode($body, true, 512, JSON_THROW_ON_ERROR) : $body;
                $file = Ip::parseRangeFile($url, $body);
                if ($file['cidrs'] !== []) {
                    $out[$url] = $file;
                }
            } catch (\Throwable) { /* Unavailable sources must never imply impersonation. */
            }
        }

        return $out;
    }
}

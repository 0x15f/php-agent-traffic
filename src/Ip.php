<?php

declare(strict_types=1);

namespace AgentTraffic;

final class Ip
{
    private static function packed(string $ip): string|false
    {
        $ip = explode('%', trim($ip), 2)[0];

        return @inet_pton($ip);
    }

    public static function normalize(string $ip): ?string
    {
        $s = trim($ip);
        if ($s === '' || str_contains($s, ',')) {
            return null;
        }
        if (preg_match('/^\[([^\]]+)\](?::\d+)?$/', $s, $m) || preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $s, $m)) {
            $s = $m[1];
        }
        $packed = self::packed($s);
        if ($packed === false) {
            return null;
        }
        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10)."\xff\xff") {
            return inet_ntop(substr($packed, 12));
        }

        return $s;
    }

    public static function inCidr(string $ip, string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) > 2) {
            return false;
        }
        $a = self::packed($ip);
        $b = self::packed($parts[0]);
        if ($a === false || $b === false || strlen($a) !== strlen($b)) {
            return false;
        }
        $raw = $parts[1] ?? (string) (strlen($a) * 8);
        if (! ctype_digit($raw) || (int) $raw > strlen($a) * 8) {
            return false;
        }
        $bits = (int) $raw;
        $bytes = intdiv($bits, 8);
        if (substr($a, 0, $bytes) !== substr($b, 0, $bytes)) {
            return false;
        }
        $remaining = $bits % 8;

        return $remaining === 0 || (ord($a[$bytes]) & (255 << (8 - $remaining))) === (ord($b[$bytes]) & (255 << (8 - $remaining)));
    }

    public static function parseRangeFile(string $url, array $body): array
    {
        $cidrs = [];
        foreach ($body['prefixes'] ?? [] as $p) {
            $cidr = $p['ipv4Prefix'] ?? $p['ipv6Prefix'] ?? null;
            if (is_string($cidr) && $cidr !== '' && self::inCidr(explode('/', $cidr)[0], $cidr)) {
                $cidrs[] = $cidr;
            }
        }
        $out = ['url' => $url, 'cidrs' => $cidrs];
        if (isset($body['creationTime'])) {
            $out['createdAt'] = $body['creationTime'];
        }

        return $out;
    }
}

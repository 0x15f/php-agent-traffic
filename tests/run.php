<?php

declare(strict_types=1);

require __DIR__.'/../src/AgentTraffic.php';
require __DIR__.'/../src/Ip.php';

use AgentTraffic\AgentTraffic;
use AgentTraffic\Ip;

$count = 0;
function check(mixed $actual, mixed $expected, string $label): void
{
    global $count;
    $count++;
    if ($actual !== $expected) {
        throw new RuntimeException($label."\nExpected: ".json_encode($expected)."\nActual: ".json_encode($actual));
    }
}
function canonical(array $value): array
{
    ksort($value);

    return $value;
}
foreach (json_decode(file_get_contents(__DIR__.'/fixtures.json'), true, 512, JSON_THROW_ON_ERROR) as $i => $case) {
    check(canonical(AgentTraffic::classify($case['input'], $case['options'])), canonical($case['result']), "Upstream parity case $i");
}
foreach (AgentTraffic::agents() as $agent) {
    foreach ($agent['examples'] as $ua) {
        $hits = [];
        foreach (AgentTraffic::patterns() as $category => $pattern) {
            if (preg_match($pattern, $ua)) {
                $hits[] = $category;
            }
        }
        check($hits, [$agent['category']], "Pattern: $ua");
    }
}
foreach ([['text/markdown', true], ['text/html, text/markdown;q=0.9', false], ['text/markdown;q=0, text/html', false], ['text/html;q=bogus, text/markdown;q=0.5', false], ['text/html;q=0.5, text/markdown', true]] as [$accept, $expected]) {
    check(AgentTraffic::prefersMarkdown($accept), $expected, $accept);
}
foreach ([['::ffff:1.2.3.4', '1.2.3.4'], ['1.2.3.4:80', '1.2.3.4'], ['[2001:db8::1]:443', '2001:db8::1'], ['1.2.3.4, 5.6.7.8', null], ['nope', null]] as [$ip, $expected]) {
    check(Ip::normalize($ip), $expected, $ip);
}
foreach ([['10.1.2.3', '10.0.0.0/8', true], ['11.1.2.3', '10.0.0.0/8', false], ['2001:db8::1', '2001:db8::/32', true], ['2001:db9::1', '2001:db8::/32', false], ['1.2.3.4', '0.0.0.0/0', true], ['1.2.3.4', '1.2.3.4/33', false], ['1.2.3.4', '::/0', false], ['::1', '::1/128', true]] as [$ip, $cidr, $expected]) {
    check(Ip::inCidr($ip, $cidr), $expected, "$ip in $cidr");
}
$loaded = AgentTraffic::loadIpRanges(static function ($url) {
    if ($url !== 'https://openai.com/gptbot.json') {
        throw new RuntimeException('Offline');
    }

    return json_encode(['creationTime' => '2026-11-18T00:00:00Z', 'prefixes' => [['ipv4Prefix' => '132.196.86.0/24'], ['ipv6Prefix' => '2a01:111::/32'], ['ipv4Prefix' => 'broken/99']]]);
});
check(count($loaded), 1, 'Failed sources skipped');
check(count($loaded['https://openai.com/gptbot.json']['cidrs']), 2, 'Malformed CIDR skipped');
check(AgentTraffic::loadIpRanges(fn () => 'invalid json'), [], 'Invalid JSON skipped');
check(AgentTraffic::classify(['headers' => ['USER-AGENT' => ['curl/8.0']]])['name'], 'curl', 'Array headers');
echo "$count checks passed\n";

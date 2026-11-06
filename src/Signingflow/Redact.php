<?php

declare(strict_types=1);

namespace Signingflow;

final class Redact
{
    private const SECRET_KEY = '/df_sk_[A-Za-z0-9_-]+/';

    private const BEARER = '/Bearer\s+\S+/i';

    private const SIGNED_QUERY = '/([?&](?:X-Goog-Signature|Signature|sig|token)=)[^&\s"]+/i';

    private const PLACEHOLDER = 'df_sk_redacted';

    public static function text(string $value, string $secret = ''): string
    {
        foreach (self::forms($secret) as $form) {
            $value = str_replace($form, self::PLACEHOLDER, $value);
        }
        $value = preg_replace(self::SECRET_KEY, self::PLACEHOLDER, $value) ?? $value;
        $value = preg_replace(self::BEARER, 'Bearer [redacted]', $value) ?? $value;

        return preg_replace(self::SIGNED_QUERY, '$1[redacted]', $value) ?? $value;
    }

    public static function message(string $value, string $secret = ''): string
    {
        $cleaned = self::text($value, $secret);
        if (strlen($cleaned) <= 500) {
            return $cleaned;
        }

        return substr($cleaned, 0, 500).'…';
    }

    /** @param list<FieldViolation> $items
     * @return list<FieldViolation>
     */
    public static function violations(array $items, string $secret = ''): array
    {
        $out = [];
        foreach ($items as $item) {
            $out[] = new FieldViolation(
                self::message($item->field, $secret),
                self::message($item->description, $secret),
            );
        }

        return $out;
    }

    /** @return list<string> */
    private static function forms(string $secret): array
    {
        if ($secret === '') {
            return [];
        }
        $forms = [];
        foreach ([$secret, rawurlencode($secret), urlencode($secret)] as $form) {
            if ($form !== '' && !in_array($form, $forms, true)) {
                $forms[] = $form;
            }
        }
        usort($forms, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        return $forms;
    }
}

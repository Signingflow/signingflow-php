<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Signingflow\APIError;
use Signingflow\AuthenticationError;
use Signingflow\Client;
use Signingflow\Clock;
use Signingflow\Config;
use Signingflow\ConnectionError;
use Signingflow\IdempotencyError;
use Signingflow\InvalidRequestError;
use Signingflow\Jail;
use Signingflow\Pagination;
use Signingflow\Path;
use Signingflow\PermissionError;
use Signingflow\RateLimitError;
use Signingflow\Redact;
use Signingflow\SignatureVerificationError;
use Signingflow\Status;
use Signingflow\WebhookUrl;

use function Signingflow\constructEvent;
use function Signingflow\signingSecretOf;

final class SdkTest extends TestCase
{
    private const ENVELOPE = 'envelopes/11111111-1111-4111-8111-111111111111';

    private const STORAGE = 'storages/22222222-2222-4222-8222-222222222222';

    private const FILE_ID = '22222222-2222-4222-8222-222222222222';

    private const TEMPLATE = 'templates/33333333-3333-4333-8333-333333333333';

    private const HOOK = 'webhookUrls/44444444-4444-4444-8444-444444444444';

    private const DELIVERY = 'webhooks/55555555-5555-4555-8555-555555555555';

    private static string $cert;

    private static string $key;

    /** @var list<LocalServer> */
    private array $servers = [];

    public static function setUpBeforeClass(): void
    {
        self::$cert = sys_get_temp_dir().'/signingflow-php-test.pem';
        self::$key = sys_get_temp_dir().'/signingflow-php-test.key';
        if (!is_file(self::$cert)) {
            $command = 'openssl req -x509 -newkey rsa:2048 -keyout '.escapeshellarg(self::$key).' -out '.escapeshellarg(self::$cert).' -days 1 -nodes -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1';
            exec($command, $output, $code);
            if ($code !== 0) {
                throw new RuntimeException('openssl failed');
            }
        }
    }

    protected function tearDown(): void
    {
        Clock::reset();
        Jail::reset();
        foreach ($this->servers as $server) {
            $server->stop();
        }
    }

    public function testConfigRejectsUnsafeValues(): void
    {
        $base = ['workspace_id' => 'ws', 'env' => 'sandbox'];
        foreach ([
            ['', 'API key is required.'],
            ["df_sk_\nlive", 'invalid header value'],
            ["df_sk_\rlive", 'invalid header value'],
            ["df_sk_\0live", 'invalid header value'],
        ] as [$key, $message]) {
            try {
                new Config($key, $base);
                self::fail('accepted '.$key);
            } catch (InvalidRequestError $error) {
                self::assertSame($message, $error->getMessage());
            }
        }
        $this->expectException(InvalidRequestError::class);
        new Config('df_sk_live', ['workspace_id' => '', 'env' => 'sandbox']);
    }

    public function testConfigMatrix(): void
    {
        $cases = [
            [['workspace_id' => 'ws', 'env' => 'live'], 'LIVE'],
            [['workspace_id' => 'ws', 'env' => 'LIVE'], 'LIVE'],
            [['workspace_id' => 'ws', 'env' => 'qa'], null],
            [['workspace_id' => "w\rs", 'env' => 'sandbox'], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'channel' => "ba\nd"], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'funnel' => "ba\0d"], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'timeout' => true], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'timeout' => 0], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'timeout' => '1'], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'max_network_retries' => -1], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'max_network_retries' => true], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'base_url' => 'http://api.signingflow.com'], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'base_url' => 'https://user:pass@api.signingflow.com'], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'base_url' => 'https://API.SIGNINGFLOW.COM'], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'base_url' => "https://api.signingflow.com\0/x"], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'base_url' => 'https://evil.example'], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'base_url' => 'https://evil.example', 'allow_custom_base_url' => true], 'SANDBOX'],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'upload_hosts' => ['localhost']], null],
            [['workspace_id' => 'ws', 'env' => 'sandbox', 'upload_hosts' => ['.bad.com']], null],
        ];
        foreach ($cases as [$options, $env]) {
            if ($env === null) {
                try {
                    new Config('df_sk_live', $options);
                    self::fail(json_encode($options));
                } catch (InvalidRequestError) {
                    self::assertTrue(true);
                }
                continue;
            }
            $config = new Config('df_sk_live', $options);
            self::assertSame($env, $config->wireEnv);
        }
        $custom = new Config('df_sk_live', [
            'workspace_id' => 'ws',
            'env' => 'sandbox',
            'upload_hosts' => ['', 'files.example.com'],
            'timeout' => 1.5,
            'max_network_retries' => 0,
            'ca_bundle' => '/tmp/ca.pem',
        ]);
        self::assertSame(['files.example.com'], $custom->uploadHosts);
        self::assertSame(1.5, $custom->timeout);
        self::assertSame(0, $custom->retries);
        self::assertSame('/tmp/ca.pem', $custom->caBundle);
    }

    public function testQuerySecretAndUploadUrlAndRetry(): void
    {
        $secret = 'df_sk_a/b c+';
        self::assertTrue(Path::containsSecret('pageToken='.rawurlencode($secret), $secret));
        self::assertTrue(Path::containsSecret('directory='.urlencode($secret), $secret));
        self::assertTrue(Path::containsSecret('readMask=%zz', $secret));
        self::assertFalse(Path::containsSecret('directory=needAction', $secret));
        self::assertSame('https://storage.googleapis.com/bucket/a?sig=1', Path::allowedUploadUrl('https://storage.googleapis.com/bucket/a?sig=1', ['storage.googleapis.com']));
        self::assertSame('https://a.storage.googleapis.com/x', Path::allowedUploadUrl('https://a.storage.googleapis.com/x', ['storage.googleapis.com']));
        foreach (['http://storage.googleapis.com/x', 'https://user:pass@storage.googleapis.com/x', 'https://evil.com/x', 'https://storage.googleapis.com./x', "https://storage.googleapis.com/x\0"] as $url) {
            try {
                Path::allowedUploadUrl($url, ['storage.googleapis.com']);
                self::fail($url);
            } catch (InvalidRequestError) {
                self::assertTrue(true);
            }
        }
        $now = new DateTimeImmutable('2026-11-06T00:00:00Z');
        self::assertSame(0.0, Path::retryDelay('2020-01-01T00:00:00Z', '', $now));
        self::assertSame(60.0, Path::retryDelay('2099-01-01T00:00:00Z', '', $now));
        self::assertSame(0.0, Path::retryDelay('not-a-date', '', $now));
        $later = $now->modify('+4 seconds');
        self::assertSame(4.0, Path::retryDelay('', $later->format('Y-m-d\TH:i:s\Z'), $now));
        self::assertNull(Path::parseRetry(''));
        try {
            Path::fill('/v1/{name}:send', []);
            self::fail('missing');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
        try {
            Path::fill('/v1/{name}:send', ['name' => 'envelopes/../x']);
            self::fail('dots');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
        self::assertSame('https://api.signingflow.com/v1/envelopes?directory=need%20Action', Path::resolve('https://api.signingflow.com', '/v1/envelopes', ['directory' => 'need Action', 'pageToken' => '']));
    }

    public function testRedactsExactKeyBeforeGenericPattern(): void
    {
        $secret = 'df_sk_a/b c+';
        $text = Redact::message($secret.' '.rawurlencode($secret).' '.urlencode($secret).' Bearer abc df_sk_other', $secret);
        self::assertStringNotContainsString($secret, $text);
        self::assertStringNotContainsString('/b c+', $text);
        self::assertStringNotContainsString('c+', $text);
        self::assertStringNotContainsString('%2F', $text);
        self::assertStringContainsString('df_sk_redacted', $text);
        $long = Redact::message(str_repeat('A', 600));
        self::assertStringEndsWith('…', $long);
        self::assertSame(500 + strlen('…'), strlen($long));
    }

    public function testPaginationKeepsTheLoaderAndStops(): void
    {
        try {
            Pagination::pageSize(0);
            self::fail('zero');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
        foreach ([true, 1.5, '10', 1001] as $bad) {
            try {
                Pagination::pageSize($bad);
                self::fail(var_export($bad, true));
            } catch (InvalidRequestError) {
                self::assertTrue(true);
            }
        }
        self::assertSame(10, Pagination::pageSize(null));
        self::assertSame('next', Pagination::nextToken(['nextPageToken' => 'next']));
        $pages = 0;
        $list = new Signingflow\ApiList([1], 'a', function (string $token) use (&$pages): Signingflow\ApiList {
            $pages++;
            if ($token === 'a') {
                return new Signingflow\ApiList([2], 'a');
            }

            return new Signingflow\ApiList([], '');
        });
        $seen = [];
        foreach ($list->all() as $item) {
            $seen[] = $item;
        }
        self::assertSame([1, 2], $seen);
        $many = new Signingflow\ApiList([0], 't', function (string $token): Signingflow\ApiList {
            return new Signingflow\ApiList([$token], $token.'x');
        });
        try {
            foreach ($many->all() as $ignored) {
            }
            self::fail('pages');
        } catch (InvalidRequestError $error) {
            self::assertSame('Too many pages.', $error->getMessage());
        }
    }

    public function testStatusWalksNestedMetadata(): void
    {
        $body = ['code' => 3, 'error' => ['details' => [['metadata' => ['resource_id' => 'envelopes/abc', 'trace_code' => 'T1'], 'fieldViolations' => [['field' => 'name', 'description' => 'bad']]]]]];
        self::assertSame('envelopes/abc', Status::resourceName($body));
        self::assertSame('T1', Status::traceCode($body));
        self::assertSame(3, Status::grpcCode($body));
        self::assertCount(1, Status::fieldViolations($body));
        self::assertTrue(Status::mentionsIdempotency(['message' => 'Idempotency conflict']));
        self::assertFalse(Status::mentionsIdempotency([]));
        self::assertSame('', Status::serverMessage([1, 2]));
        self::assertNull(Status::asInt(true));
        self::assertSame(2, Status::asInt(2.0));
        self::assertSame(2, Status::asInt('2'));
    }

    public function testJailRefusesLinksAndReadsARegularFile(): void
    {
        $root = sys_get_temp_dir().'/sf-jail-'.bin2hex(random_bytes(4));
        mkdir($root);
        file_put_contents($root.'/ok.pdf', 'OK');
        $secret = sys_get_temp_dir().'/sf-secret-'.bin2hex(random_bytes(4));
        file_put_contents($secret, 'SECRET');
        try {
            self::assertSame('OK', Jail::read($root, 'ok.pdf'));
            foreach ([
                $secret,
                "ok.pdf\0.txt",
                '../'.basename($secret),
                'nested/../../'.basename($secret),
            ] as $path) {
                try {
                    Jail::read($root, $path);
                    self::fail($path);
                } catch (InvalidRequestError $error) {
                    self::assertNotSame('SECRET', $error->getMessage());
                }
            }
            try {
                Jail::read('', 'ok.pdf');
                self::fail('root');
            } catch (InvalidRequestError $error) {
                self::assertSame('A filesystem path requires upload_root.', $error->getMessage());
            }
            symlink($secret, $root.'/link.pdf');
            try {
                $read = Jail::read($root, 'link.pdf');
                self::assertNotSame('SECRET', $read);
                self::fail('symlink returned');
            } catch (InvalidRequestError $error) {
                self::assertNotSame('SECRET', $error->getMessage());
            }
            link($root.'/ok.pdf', $root.'/hard.pdf');
            try {
                Jail::read($root, 'hard.pdf');
                self::fail('hard link');
            } catch (InvalidRequestError $error) {
                self::assertSame('The file must not be a hard link.', $error->getMessage());
            }
            $fifo = $root.'/pipe.pdf';
            if (function_exists('posix_mkfifo')) {
                posix_mkfifo($fifo, 0600);
                try {
                    Jail::read($root, 'pipe.pdf');
                    self::fail('fifo');
                } catch (InvalidRequestError) {
                    self::assertTrue(true);
                }
            }
            $sparse = $root.'/big.pdf';
            $handle = fopen($sparse, 'wb');
            ftruncate($handle, 25 * 1024 * 1024 + 1);
            fclose($handle);
            try {
                Jail::read($root, 'big.pdf');
                self::fail('size');
            } catch (InvalidRequestError $error) {
                self::assertSame('The file is larger than 25 MB.', $error->getMessage());
            }
            Jail::$ffiDisabled = true;
            try {
                Jail::read($root, 'ok.pdf');
                self::fail('ffi');
            } catch (InvalidRequestError $error) {
                self::assertSame('The file could not be read.', $error->getMessage());
            }
            Jail::reset();
            Jail::$nofollowOverride = 0;
            try {
                Jail::read($root, 'ok.pdf');
                self::fail('flag');
            } catch (InvalidRequestError $error) {
                self::assertSame('The file could not be read.', $error->getMessage());
            }
        } finally {
            Jail::reset();
            exec('rm -rf '.escapeshellarg($root).' '.escapeshellarg($secret));
        }
    }

    public function testSendDocumentAndUploadContract(): void
    {
        $server = $this->server([]);
        $server->rules([
            ['contains' => 'batchAddStorage', 'json' => ['storages' => [['name' => self::STORAGE, 'pre_signed_url' => 'https://127.0.0.1:'.$server->port.'/bucket/a']]]],
            ['method' => 'PUT', 'status' => 412, 'body' => ''],
            ['contains' => 'batchAcknowledgeUpload', 'json' => []],
            ['contains' => 'addEnvelope', 'json' => ['envelope' => ['name' => self::ENVELOPE, 'display_name' => 'Contract']]],
            ['contains' => ':view', 'json' => ['name' => self::ENVELOPE, 'display_name' => 'Contract', 'documents' => [['uid' => 'doc-1', 'display_name' => 'Contract']], 'compliance' => ['profile' => 'QES']]],
            ['method' => 'PATCH', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':send', 'json' => ['name' => self::ENVELOPE, 'sent_time' => '2026-11-06T00:00:00Z']],
        ]);
        $client = $this->client($server, ['upload_hosts' => ['127.0.0.1']]);
        $sent = $client->envelopes->sendDocument([
            'title' => 'Contract',
            'file' => '%PDF',
            'filename' => 'contract.pdf',
            'recipients' => [['name' => 'Ada', 'email' => 'ada@example.com']],
            'message' => 'Please sign',
        ]);
        self::assertSame(self::ENVELOPE, $sent->name);
        $seen = $server->seen();
        $put = null;
        foreach ($seen as $row) {
            if ($row['method'] === 'PUT') {
                $put = $row;
            }
            self::assertSame('', $server->header($row['headers'], 'Accept-Encoding') === 'identity' || $row['method'] === 'PUT' ? '' : 'bad encoding');
        }
        self::assertNotNull($put);
        self::assertSame('application/pdf', $server->header($put['headers'], 'Content-Type'));
        self::assertSame('0', $server->header($put['headers'], 'x-goog-if-generation-match'));
        self::assertSame('', $server->header($put['headers'], 'Authorization'));
        $add = $seen[0];
        self::assertSame('Bearer df_sk_test', $server->header($add['headers'], 'Authorization'));
        self::assertSame('ws', $server->header($add['headers'], 'X-Request-Workspace-Id'));
        self::assertSame('SANDBOX', $server->header($add['headers'], 'X-Request-Env'));
        self::assertSame('signingflow-php/0.1.0', $server->header($add['headers'], 'X-Request-Source'));
        self::assertSame('identity', $server->header($add['headers'], 'Accept-Encoding'));
        self::assertStringNotContainsString('X-Api-Key', json_encode($add['headers']));
    }

    public function testRefusesEncodedApiKeyBeforeCalling(): void
    {
        $secret = 'df_sk_a/b c+';
        $server = $this->server([['json' => ['envelopes' => []]]]);
        $client = $this->client($server, ['api_key' => $secret]);
        try {
            $client->envelopes->list(['directory' => $secret]);
            self::fail('query');
        } catch (InvalidRequestError $error) {
            self::assertSame('The API key must not be sent in the query string.', $error->getMessage());
        }
        self::assertSame([], $server->seen());
    }

    public function testRedactsSlashKeyFromAnApiError(): void
    {
        $secret = 'df_sk_a/b c+';
        $server = $this->server([[
            'status' => 400,
            'json' => [
                'message' => $secret.' '.rawurlencode($secret).' '.urlencode($secret),
                'details' => [['fieldViolations' => [['field' => $secret, 'description' => 'Bearer '.$secret]]]],
            ],
        ]]);
        $client = $this->client($server, ['api_key' => $secret]);
        try {
            $client->envelopes->retrieve(self::ENVELOPE);
            self::fail('error');
        } catch (InvalidRequestError $error) {
            $text = $error->getMessage().$error->fieldViolations[0]->field.$error->fieldViolations[0]->description;
            self::assertStringNotContainsString($secret, $text);
            self::assertStringNotContainsString('/b c+', $text);
            self::assertStringNotContainsString('c+', $text);
        }
    }

    public function testRetriesIdempotentCallsAndNotUpdates(): void
    {
        $slept = 0;
        Clock::$sleepFn = static function (float $seconds) use (&$slept): void {
            $slept += $seconds;
        };
        $server = $this->server([
            ['contains' => 'addEnvelope', 'status' => 500, 'json' => ['message' => 'down'], 'headers' => ['Rate-Limit-Retry-After' => '2099-01-01T00:00:00Z']],
            ['contains' => ':remind', 'status' => 500, 'json' => ['message' => 'down']],
        ]);
        $client = $this->client($server, ['retries' => 1]);
        try {
            $client->envelopes->create(['display_name' => 'A', 'storage_id' => self::FILE_ID]);
            self::fail('create');
        } catch (APIError) {
            self::assertSame(60.0, $slept);
        }
        $creates = 0;
        foreach ($server->seen() as $row) {
            if (str_contains($row['target'], 'addEnvelope')) {
                $creates++;
            }
        }
        self::assertSame(2, $creates);
        $before = count($server->seen());
        try {
            $client->envelopes->remind(self::ENVELOPE);
            self::fail('remind');
        } catch (APIError) {
            self::assertCount($before + 1, $server->seen());
        }
    }

    public function testResponseLimitsAndRedirects(): void
    {
        $chunk = $this->server([['mode' => 'chunk']]);
        try {
            $this->client($chunk)->envelopes->retrieve(self::ENVELOPE);
            self::fail('chunk');
        } catch (APIError $error) {
            self::assertSame('The API response is larger than 8 MB.', $error->getMessage());
        }
        $declared = $this->server([['mode' => 'clen']]);
        try {
            $this->client($declared)->envelopes->retrieve(self::ENVELOPE);
            self::fail('clen');
        } catch (APIError $error) {
            self::assertSame('The API response is larger than 8 MB.', $error->getMessage());
        }
        $gzip = $this->server([['gzip' => true, 'json' => ['name' => self::ENVELOPE]]]);
        try {
            $this->client($gzip)->envelopes->retrieve(self::ENVELOPE);
            self::fail('gzip');
        } catch (APIError) {
            self::assertTrue(true);
        }
        $short = $this->server([['mode' => 'short']]);
        try {
            $envelope = $this->client($short)->envelopes->retrieve(self::ENVELOPE);
            self::fail('short returned '.$envelope->name);
        } catch (ConnectionError|APIError) {
            self::assertTrue(true);
        }
        $redirect = $this->server([['mode' => 'redirect']]);
        try {
            $this->client($redirect)->envelopes->retrieve(self::ENVELOPE);
            self::fail('redirect');
        } catch (InvalidRequestError|APIError) {
            self::assertCount(1, $redirect->seen());
        }
    }

    public function testUploadRetriesAndRejectsEarlyStatus(): void
    {
        $server = $this->server([]);
        $server->rules([
            ['contains' => 'batchAddStorage', 'json' => ['storages' => [['name' => self::STORAGE, 'preSignedUrl' => 'https://127.0.0.1:'.$server->port.'/bucket/a']]]],
            ['method' => 'PUT', 'status' => 199, 'body' => ''],
        ]);
        try {
            $this->client($server, ['retries' => 0, 'upload_hosts' => ['127.0.0.1']])->files->create(['file' => 'A', 'filename' => 'a.txt']);
            self::fail('199');
        } catch (APIError $error) {
            self::assertSame('Uploading the file to storage failed.', $error->getMessage());
        }
        $retry = $this->server([
            ['contains' => 'batchAddStorage', 'json' => ['storages' => [['name' => self::STORAGE, 'pre_signed_url' => 'https://evil.example/a']]]],
        ]);
        try {
            $this->client($retry)->files->create(['file' => 'A', 'filename' => 'a.txt']);
            self::fail('host');
        } catch (InvalidRequestError) {
            self::assertCount(1, $retry->seen());
        }
    }

    public function testSendRecoveryAndErrors(): void
    {
        $server = $this->server([
            ['contains' => ':use', 'json' => ['name' => self::ENVELOPE, 'display_name' => 'Kept']],
            ['method' => 'PATCH', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':send', 'status' => 409, 'json' => ['message' => 'idempotency replay', 'details' => [['metadata' => ['resource_id' => self::ENVELOPE]]]]],
            ['contains' => ':view', 'json' => ['name' => self::ENVELOPE, 'display_name' => 'Kept', 'documents' => [['uid' => 'doc-1', 'display_name' => 'Kept']]]],
        ]);
        $viewed = $this->client($server)->envelopes->sendFromTemplate([
            'template' => self::TEMPLATE,
            'recipients' => [['name' => 'Ada', 'email' => 'ada@example.com']],
        ]);
        self::assertSame('Kept', $viewed->displayName);

        $closed = $this->server([
            ['contains' => ':use', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':view', 'json' => ['name' => self::ENVELOPE, 'documents' => [['uid' => 'doc-1', 'display_name' => 'Kept']]]],
            ['method' => 'PATCH', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':send', 'mode' => 'close'],
        ]);
        try {
            $this->client($closed, ['retries' => 0])->envelopes->sendFromTemplate([
                'template' => self::TEMPLATE,
                'recipients' => [['name' => 'Ada', 'email' => 'ada@example.com']],
            ]);
            self::fail('down');
        } catch (ConnectionError $error) {
            self::assertSame(self::ENVELOPE, $error->envelopeName);
        }

        $auth = $this->server([['status' => 401, 'json' => ['message' => 'no']]]);
        try {
            $this->client($auth)->envelopes->retrieve(self::ENVELOPE);
            self::fail('401');
        } catch (AuthenticationError) {
            self::assertTrue(true);
        }
        $denied = $this->server([['status' => 403, 'json' => ['message' => 'no']]]);
        try {
            $this->client($denied)->envelopes->retrieve(self::ENVELOPE);
            self::fail('403');
        } catch (PermissionError) {
            self::assertTrue(true);
        }
        $rate = $this->server([['status' => 429, 'json' => ['message' => 'slow'], 'headers' => ['Rate-Limit-Reset-After' => '2']]]);
        try {
            $this->client($rate, ['retries' => 0])->envelopes->retrieve(self::ENVELOPE);
            self::fail('429');
        } catch (RateLimitError $error) {
            self::assertSame('2', $error->retryAfter);
        }
        $other = $this->server([['status' => 409, 'json' => ['message' => 'conflict']]]);
        try {
            $this->client($other)->envelopes->retrieve(self::ENVELOPE);
            self::fail('409');
        } catch (InvalidRequestError $error) {
            self::assertNotInstanceOf(IdempotencyError::class, $error);
        }
    }

    public function testConnectionRecoveryUsesTheSendWindow(): void
    {
        $now = new DateTimeImmutable('2026-11-06T00:00:10Z');
        Clock::$nowFn = static fn () => $now;
        $server = $this->server([
            ['contains' => ':use', 'json' => ['name' => self::ENVELOPE]],
            ['method' => 'PATCH', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':send', 'mode' => 'close'],
            ['contains' => ':view', 'json' => ['name' => self::ENVELOPE, 'sent_time' => '2026-11-06T00:00:10Z', 'documents' => [['uid' => 'doc-1', 'display_name' => 'Kept']]]],
        ]);
        $recovered = $this->client($server, ['timeout' => 2, 'retries' => 0])->envelopes->sendFromTemplate([
            'template' => self::TEMPLATE,
            'recipients' => [['name' => 'Ada', 'email' => 'ada@example.com']],
        ]);
        self::assertSame(self::ENVELOPE, $recovered->name);
        self::assertNotSame('', $recovered->sentTime);
    }

    public function testOldSentTimeIsNotRecovery(): void
    {
        Clock::$nowFn = static fn (): DateTimeImmutable => new DateTimeImmutable('2026-11-06T00:10:00Z');
        $server = $this->server([
            ['contains' => ':use', 'json' => ['name' => self::ENVELOPE]],
            ['method' => 'PATCH', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':send', 'mode' => 'close'],
            ['contains' => ':view', 'json' => ['name' => self::ENVELOPE, 'sent_time' => '2020-01-01T00:00:00Z', 'documents' => [['uid' => 'doc-1', 'display_name' => 'Kept']]]],
        ]);
        try {
            $this->client($server, ['retries' => 0])->envelopes->sendFromTemplate([
                'template' => self::TEMPLATE,
                'recipients' => [['name' => 'Ada', 'email' => 'ada@example.com']],
            ]);
            self::fail('old');
        } catch (ConnectionError $error) {
            self::assertSame(self::ENVELOPE, $error->envelopeName);
        }
    }

    public function testTemplateListDownloadAndWebhooks(): void
    {
        $server = $this->server([
            ['contains' => ':use', 'json' => ['name' => self::ENVELOPE, 'display_name' => 'From template']],
            ['contains' => ':send', 'json' => ['name' => self::ENVELOPE, 'sent_time' => '2026-11-06T00:00:00Z']],
            ['method' => 'PATCH', 'json' => ['name' => self::ENVELOPE]],
            ['contains' => ':test', 'json' => ['name' => self::HOOK, 'signingSecret' => 'once']],
            ['contains' => 'webhookUrls:add', 'json' => ['name' => self::HOOK, 'displayName' => 'Hooks', 'httpRequestUri' => 'https://example.com/hook', 'events' => ['envelope.completed'], 'signing_secret' => 'whsec']],
            ['contains' => 'webhookUrls/', 'json' => ['name' => self::HOOK, 'signingSecret' => 'hidden', 'http_request_uri' => 'https://example.com/hook']],
            ['contains' => 'webhooks?', 'json' => ['webhooks' => [['name' => self::DELIVERY, 'event' => 'envelope.completed']], 'nextPageToken' => 'p2']],
            ['contains' => 'webhooks/', 'json' => ['name' => self::DELIVERY, 'event' => 'envelope.completed']],
            ['contains' => 'envelopes?', 'json' => ['envelopes' => [['name' => self::ENVELOPE]], 'next_page_token' => '']],
            ['contains' => ':download', 'json' => ['uri' => 'https://files.example/doc', 'download_time' => '2026-11-06T00:00:00Z', 'etag' => 'e1']],
            ['contains' => ':view', 'json' => ['name' => self::ENVELOPE, 'display_name' => 'From template', 'documents' => [['uid' => 'doc-1', 'display_name' => 'From template']], 'progress' => ['state' => 'COMPLETED']]],
        ]);
        $client = $this->client($server);
        $draft = $client->envelopes->sendFromTemplate([
            'template' => self::TEMPLATE,
            'recipients' => [['name' => 'Ada', 'email' => 'ada@example.com']],
        ]);
        self::assertSame(self::ENVELOPE, $draft->name);
        $page = $client->envelopes->list(['directory' => 'needAction', 'page_size' => 2]);
        self::assertSame(self::ENVELOPE, $page->data[0]->name);
        $ready = $client->envelopes->downloadCompleted(self::ENVELOPE);
        self::assertSame('https://files.example/doc', $ready->uri);
        self::assertSame('e1', $ready->etag);
        $created = $client->webhookUrls->create([
            'display_name' => 'Hooks',
            'http_request_uri' => 'https://example.com/hook',
            'events' => ['envelope.completed'],
        ]);
        self::assertSame('whsec', $created->signingSecret);
        $viewed = $client->webhookUrls->retrieve(self::HOOK);
        self::assertSame('', $viewed->signingSecret);
        self::assertSame('once', $client->webhookUrls->test(self::HOOK)->signingSecret);
        $deliveries = $client->webhookDeliveries->list(['page_size' => 1]);
        self::assertSame('p2', $deliveries->nextPageToken);
        self::assertSame(self::DELIVERY, $client->webhookDeliveries->retrieve(self::DELIVERY)->name);
        $body = '{"event":"envelope.completed"}';
        $signature = hash_hmac('sha256', $body, 'whsec');
        $event = constructEvent($body, strtoupper($signature), 'whsec');
        self::assertSame('envelope.completed', $event->payload['event']);
        self::assertSame(hash('sha256', $body), $event->bodySha256);
        self::assertSame('whsec', signingSecretOf(new WebhookUrl(signingSecret: 'whsec')));
        self::assertSame('once', signingSecretOf(['signingSecret' => 'once']));
    }

    public function testWebhookAndInputGuards(): void
    {
        try {
            constructEvent(['event' => 'x'], 'sig', 'secret');
            self::fail('raw');
        } catch (SignatureVerificationError $error) {
            self::assertSame('Pass the raw request body.', $error->getMessage());
        }
        try {
            constructEvent('{}', 'sig', '');
            self::fail('empty');
        } catch (SignatureVerificationError) {
            self::assertTrue(true);
        }
        try {
            constructEvent('not-json', hash_hmac('sha256', 'not-json', 'secret'), 'secret');
            self::fail('json');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
        $previous = hash_hmac('sha256', '{}', 'old');
        $event = constructEvent('{}', 'wrong', 'new', 'old', $previous);
        self::assertIsArray($event->payload);
        $client = new Client('df_sk_test', ['workspace_id' => 'ws', 'env' => 'sandbox']);
        foreach ([
            static fn () => $client->envelopes->create(['display_name' => '', 'storage_id' => 'x']),
            static fn () => $client->envelopes->create(['display_name' => 'A', 'storage_id' => '']),
            static fn () => $client->envelopes->retrieve('nope'),
            static fn () => $client->envelopes->list(['directory' => '']),
            static fn () => $client->envelopes->list(['directory' => 'needAction', 'page_size' => 0]),
            static fn () => $client->files->create([]),
            static fn () => $client->files->create(['file' => 'A', 'path' => 'a.pdf', 'filename' => 'a.pdf']),
            static fn () => $client->files->create(['file' => 'A']),
            static fn () => $client->files->create(['file' => str_repeat('A', 25 * 1024 * 1024 + 1), 'filename' => 'a.pdf']),
            static fn () => $client->templates->use('nope'),
            static fn () => $client->webhookUrls->create(['display_name' => '', 'http_request_uri' => 'https://example.com', 'events' => ['a']]),
            static fn () => $client->webhookUrls->create(['display_name' => 'A', 'http_request_uri' => 'http://example.com', 'events' => ['a']]),
            static fn () => $client->webhookUrls->create(['display_name' => 'A', 'http_request_uri' => 'https://example.com', 'events' => []]),
            static fn () => $client->webhookUrls->create(['display_name' => 'A', 'http_request_uri' => 'https://example.com', 'events' => ['a'], 'http_config' => new Signingflow\HttpConfig('NONE')]),
            static fn () => $client->webhookUrls->retrieve('nope'),
            static fn () => $client->webhookDeliveries->retrieve('nope'),
            static fn () => $client->envelopes->sendDocument(['title' => 'A', 'file' => 'A', 'filename' => 'a.pdf', 'recipients' => []]),
            static fn () => $client->envelopes->prepareDraft(['title' => '']),
        ] as $call) {
            try {
                $call();
                self::fail('accepted');
            } catch (InvalidRequestError) {
                self::assertTrue(true);
            }
        }
    }

    public function testDefaultClientRejectsTheProbeCertificate(): void
    {
        $server = $this->server([['json' => ['name' => self::ENVELOPE]]]);
        $client = new Client('df_sk_test', [
            'workspace_id' => 'ws',
            'env' => 'sandbox',
            'base_url' => 'https://127.0.0.1:'.$server->port,
            'allow_custom_base_url' => true,
            'timeout' => 2,
            'max_network_retries' => 0,
        ]);
        try {
            $client->envelopes->retrieve(self::ENVELOPE);
            self::fail('tls');
        } catch (ConnectionError) {
            self::assertTrue(true);
        }
    }

    public function testListFollowsTheNextPage(): void
    {
        $server = $this->server([
            ['contains' => 'pageToken=next', 'json' => ['envelopes' => [['name' => self::ENVELOPE, 'displayName' => 'Second']]]],
            ['contains' => 'envelopes?', 'json' => ['envelopes' => [['name' => self::ENVELOPE, 'displayName' => 'First']], 'next_page_token' => 'next']],
        ]);
        $names = [];
        foreach ($this->client($server)->envelopes->list(['directory' => 'waitingOthers'])->all() as $envelope) {
            $names[] = $envelope->displayName;
        }
        self::assertSame(['First', 'Second'], $names);
    }

    public function testMoreBranches(): void
    {
        Clock::reset();
        Clock::sleep(0);
        try {
            Signingflow\Allowlist::operation('missing');
            self::fail('operation');
        } catch (Signingflow\Error $error) {
            self::assertSame('Unknown operation.', $error->getMessage());
        }
        try {
            Signingflow\Sender::keyFor('not-a-uuid', null);
            self::fail('uuid');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
        $key = '11111111-1111-4111-8111-111111111111';
        self::assertSame($key, Signingflow\Sender::keyFor('', ['idempotencyKey' => ' '.$key.' ']));
        $html = $this->server([['content_type' => 'application/octet-stream', 'body' => '<p>no</p>']]);
        try {
            $this->client($html)->envelopes->retrieve(self::ENVELOPE);
            self::fail('html');
        } catch (APIError $error) {
            self::assertSame('The API returned a non-JSON body.', $error->getMessage());
        }
        $broken = $this->server([['content_type' => 'application/json', 'body' => '{']]);
        try {
            $this->client($broken)->envelopes->retrieve(self::ENVELOPE);
            self::fail('json');
        } catch (APIError $error) {
            self::assertSame('The API returned invalid JSON.', $error->getMessage());
        }
        $empty = $this->server([['body' => '', 'content_type' => 'application/json']]);
        $named = $this->client($empty)->envelopes->retrieve(self::ENVELOPE);
        self::assertSame(self::ENVELOPE, $named->name);
        $open = $this->server([['json' => ['name' => self::ENVELOPE, 'state' => 'SENT']]]);
        try {
            $this->client($open)->envelopes->downloadCompleted(self::ENVELOPE);
            self::fail('ready');
        } catch (InvalidRequestError $error) {
            self::assertSame('The signed file is not ready.', $error->getMessage());
            self::assertSame(self::ENVELOPE, $error->envelopeName);
        }
        $draft = $this->server([
            ['contains' => 'batchAddStorage', 'json' => ['storages' => [['name' => self::STORAGE, 'pre_signed_url' => 'https://127.0.0.1:0/x']]]],
        ]);
        $draft->rules([
            ['contains' => 'batchAddStorage', 'json' => ['storages' => [['name' => self::STORAGE, 'pre_signed_url' => 'https://127.0.0.1:'.$draft->port.'/x']]]],
            ['method' => 'PUT', 'status' => 200, 'body' => ''],
            ['contains' => 'batchAcknowledgeUpload', 'json' => []],
            ['contains' => 'addEnvelope', 'json' => ['uid' => '11111111-1111-4111-8111-111111111111']],
        ]);
        $prepared = $this->client($draft, ['upload_hosts' => ['127.0.0.1']])->envelopes->prepareDraft([
            'title' => 'Draft',
            'file' => 'A',
            'filename' => 'a.txt',
            'message' => 'hold',
        ]);
        self::assertSame(self::ENVELOPE, $prepared->name);
        $client = new Client('df_sk_test', ['workspace_id' => 'ws', 'env' => 'sandbox']);
        try {
            $client->webhookUrls->create([
                'display_name' => 'Hooks',
                'http_request_uri' => 'https://example.com/hook',
                'events' => ['a'],
                'http_config' => (object) ['auth' => 'BASIC'],
            ]);
            self::fail('config');
        } catch (InvalidRequestError $error) {
            self::assertSame('Leave http_config empty so the destination uses HMAC.', $error->getMessage());
        }
        try {
            constructEvent('{}', 'ab', 'secret');
            self::fail('mac');
        } catch (SignatureVerificationError) {
            self::assertTrue(true);
        }
        $sender = new Signingflow\Sender($client->config);
        try {
            $sender->exchange('GET', 'http://api.signingflow.com', null, []);
            self::fail('http');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
        try {
            $sender->putBytes('https://storage.googleapis.com/a', "text/plain\nbad", 'A');
            self::fail('mime');
        } catch (InvalidRequestError) {
            self::assertTrue(true);
        }
    }

    /** @param list<array<string, mixed>> $rules
     * @param array<string, mixed> $options
     */
    private function client(LocalServer $server, array $options = []): Client
    {
        return new Client($options['api_key'] ?? 'df_sk_test', [
            'workspace_id' => 'ws',
            'env' => 'sandbox',
            'base_url' => 'https://127.0.0.1:'.$server->port,
            'allow_custom_base_url' => true,
            'ca_bundle' => self::$cert,
            'timeout' => $options['timeout'] ?? 2,
            'max_network_retries' => $options['retries'] ?? 2,
            'channel' => 'mail',
            'funnel' => 'web',
            'upload_hosts' => $options['upload_hosts'] ?? null,
        ]);
    }

    /** @param list<array<string, mixed>> $rules */
    private function server(array $rules): LocalServer
    {
        $server = LocalServer::start(self::$cert, self::$key, $rules);
        $this->servers[] = $server;

        return $server;
    }
}

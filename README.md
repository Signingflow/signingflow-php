# signingflow

PHP SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The package talks to `https://api.signingflow.com`. Keep the API key on your server. PHP 8.3 or newer is required, with the `curl` and `json` extensions.

```json
{
  "repositories": [
    {"type": "vcs", "url": "https://github.com/Signingflow/signingflow-php"}
  ],
  "require": {
    "signingflow/signingflow": "dev-main"
  }
}
```

The Composer name is `signingflow/signingflow`. Install it from [GitHub](https://github.com/Signingflow/signingflow-php) until it is published on Packagist.

```php
$signingflow = new Signingflow\Client(getenv('SIGNINGFLOW_API_KEY'), [
    'workspace_id' => getenv('SIGNINGFLOW_WORKSPACE_ID'),
    'env' => 'sandbox',
]);

$envelope = $signingflow->envelopes->sendDocument([
    'title' => 'NDA',
    'file' => $pdfBytes,
    'filename' => 'contract.pdf',
    'recipients' => [['name' => 'Ada Lovelace', 'email' => 'ada@example.com']],
    'message' => 'Please sign',
]);
```

`file` is a string of raw bytes. `''` is an empty file. A disk path is `path`, and it is read only from `upload_root`. That directory must be one this process writes. The open refuses a symlink, a hard link, an absolute path, and a path that leaves the directory. Path reads use PHP FFI with `O_NOFOLLOW`. Run the process with `php -d ffi.enable=true`. If FFI is unavailable, a path is refused and the file is not opened. Passing bytes in `file` does not need FFI. Do not pass a path from a request field.

`env` is `sandbox` or `live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API, so the client rejects a missing environment.

`base_url` must be `https`. The host is `api.signingflow.com` unless `allow_custom_base_url` is set. A username or password on the URL is rejected. The host comparison is case-sensitive. There is no process-wide API key.

The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading once an API response passes 8 MB.

## Send and read

`envelopes->prepareDraft` stores one PDF and creates a draft. It does not email anyone.

`envelopes->sendDocument` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `envelopes->sendFromTemplate` starts from `templates/{id}`.

If update or send fails, the error includes `envelopeName` for the draft that was saved. After a timeout, the client returns the envelope only when `sentTime` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`envelopes->list(['directory' => 'needAction'])` reads pages of 10. `page_size` can be from 1 to 1000. Omitting it selects 10. `0` is rejected. `all()` walks later pages and stops after 100 follow-up pages or a repeated token.

`envelopes->downloadCompleted($name)` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `uri`, `downloadTime`, and `etag`. This client does not GET `uri`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`envelopes->remind($name)` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK raises `Signingflow\IdempotencyError` with `resourceName` when the error includes one. It does not treat that response as success.

Pass the same `idempotency_key` only to retry one request after a timeout. `update` and `remind` are not retried automatically. A query value that contains the API key is rejected, including when that key is percent-encoded.

## Webhooks

```php
$destination = $signingflow->webhookUrls->create([
    'display_name' => 'Envelope events',
    'http_request_uri' => 'https://example.com/webhooks/signingflow',
    'events' => ['DOC_ENVELOPE_COMPLETED'],
]);
$secret = Signingflow\signingSecretOf($destination);
```

Store that secret from the create response. A later `retrieve` does not include it. Do not set `http_config`. `auth` `NONE` is rejected.

```php
$event = Signingflow\constructEvent($rawBody, $signatureHeader, $secret, $previousSecret, $previousSignature);
$event->payload;
$event->bodySha256;
```

`$rawBody` must be the original request body string. The signature is lowercase hex HMAC-SHA256 of those bytes. There is no timestamp. Compare `X-Signingflow-Signature` or `X-Webhook-Signature`. During a grace window, also pass the previous header and secret. Parse JSON only after the MAC matches. `bodySha256` is the SHA-256 of those raw bytes. Store it and reject a delivery you have already seen.

## Errors

Every SDK error is a `Signingflow\Error`, which extends `Exception`.

| Type | When |
| --- | --- |
| `AuthenticationError` | HTTP 401 |
| `PermissionError` | HTTP 403 |
| `IdempotencyError` | HTTP 409 whose body says the key was already used |
| `RateLimitError` | HTTP 429 |
| `InvalidRequestError` | Any other HTTP 4xx, or a rejected argument |
| `APIError` | HTTP 5xx, or a body the client will not parse |
| `ConnectionError` | The API was not reached, including a timeout |
| `SignatureVerificationError` | A webhook MAC did not match |

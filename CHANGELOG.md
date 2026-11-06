# Changelog

## 0.1.0

First PHP SDK for sending a document, reading envelope status, downloading a completed file, and verifying webhook signatures.

Install from GitHub with a Composer VCS repository on `dev-main` until the package is on Packagist. The package name is `signingflow/signingflow`.

The API host is HTTPS `api.signingflow.com` unless a custom base URL is allowed. A file path is read only from `upload_root`, and only when FFI can open it with `O_NOFOLLOW`. A hard link and an absolute path are rejected. Byte uploads do not need FFI. `constructEvent` returns `payload` and `bodySha256` of the raw body. A 409 is an idempotency error only when the body says the key was already used. A timed-out send is returned only when `sentTime` falls in the two minutes after the call started. The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading an API response at 8 MB. A query value that contains the API key is rejected, including when that key is percent-encoded. An API error does not keep an API key that contains a slash or a space. A response that ends before its declared length is not treated as the resource.

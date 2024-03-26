[![Build Status](https://github.com/omnivector-solutions/armasec-subscriptions/actions/workflows/test_on_push.yaml/badge.svg)](https://github.com/omnivector-solutions/armasec-submissions/actions/workflows/test_on_push.yaml)


![Python Versions](https://img.shields.io/pypi/pyversions/armasec?label=python-versions&logo=python&style=plastic)
![PyPI Versions](https://img.shields.io/pypi/v/armasec?label=pypi-version&logo=python&style=plastic)
![License](https://img.shields.io/pypi/l/armasec?style=plastic)


> An [Omnivector](https://www.omnivector.io/) initiative
>
> [![omnivector-logo](https://omnivector-public-assets.s3.us-west-2.amazonaws.com/branding/omnivector-logo-text-black-horz.png)](https://www.omnivector.io/)



# Armasec Subscriptions

This plugin for [Armasec](https://github.com/omnivector-solutions/armasec) provides a
means to verify that a user accessing a secured endpoint also has an active submission.

The plugin verifies an active subscription by calling an endpoint that checking that the
user embedded in the auth token is an active subscriber. To enable the plugin, you need
only install it in your project's environment and set the environment variable
`ARMASEC_SUB_URL` to point to an endpoint that checks the user's subscription status by
comparing the `sub` claim in the access token against a list of subscribed users. The
endpoint should return a 200 if the user should have access and a 404 if the
subscription could not be found.

That's it! Once installed and configured, every secure endpoint will check for a
subscription.


## Quickstart

1. Install `armasec-subscriptions`

```bash
pip install armasec-subscriptions
```


2. Set the `ARMSEC_SUB_URL` environment variable:

```bash
export ARMSEC_SUB_URL=https://my-api.io/sub-check
```


## Additional Options

The Armasec Subscriptions plugin caches requests to the `ARMASEC_SUB_URL` for
performance reasons. The cache key is the auth token itself. By default, the requests
are cached for 15 minutes. A typical auth token's access lifespan is shorter than 15
minutes, so it's probable that the token would be expired and require a refresh before
it expires in the cache. The cache automatically removes entries that are older than
the configured "Time to live" (TTL). If you wish to change the TTL for the cache, you
may set the environment variable `ARMASEC_SUB_CACHE_TTL`. The expected values are
integers representing the number of seconds for which each entry should be retained.

The cache retains a maximum of ~1 million entries by default. If you wish to change the
maximum size of the cache, you may set the environment varaible `ARMASEC_SUB_CACHE_MAX`.
The expected values are integers representing the maximum number of entries the cache
should retain.

You may also configure the plugin to allow READ operations for all routes. To enable
this, set the `ARMASEC_SUB_ALLOW_READS` environment variable flag.

You may also configure the plugin to allow DELETE operations for all routes. To enable
this, set the `ARMASEC_SUB_ALLOW_DELETES` environment variable flag.


## License

Distributed under the MIT License. See `LICENSE` for more information.

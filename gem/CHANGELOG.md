# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-03

### Added
- Initial release
- OTLP trace export to MiniAPM server
- Error tracking with fingerprinting and parameter filtering
- W3C Trace Context support for distributed tracing
- Automatic instrumentation for:
  - Rails (ActionController, ActionView)
  - ActiveRecord
  - ActiveJob (SolidQueue, Sidekiq adapter)
  - Sidekiq
  - Rails Cache
  - Net::HTTP
  - HTTParty
  - Faraday
  - Elasticsearch
  - OpenSearch
  - Searchkick
  - Redis (redis-client and legacy redis gem)
- Async batched sending with configurable batch size and flush interval
- Sampling support with configurable sample rate
- Rails generator for easy setup (`rails g miniapm:install`)
- Testing helpers for capturing spans and errors in tests
- Health check endpoint verification
- Retry logic with exponential backoff for failed exports

### Security
- Automatic parameter filtering for sensitive data
- SQL query sanitization option
- No sensitive data logged by default

[Unreleased]: https://github.com/miniapm/miniapm-ruby/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/miniapm/miniapm-ruby/releases/tag/v0.1.0

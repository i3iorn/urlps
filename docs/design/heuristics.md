# Design note: the injection and punycode heuristics

**Status:** the code described here is unchanged as of 0.7.0. This document
explains what these two checks are trying to achieve and why they fall short,
so their fate can be decided deliberately rather than by default.

The two checks are `has_query_injection()` and `has_suspicious_punycode()` in
`src/urlps/_security/url_checks.py`.

---

## `has_query_injection()`

### The idea

URLs carry user-controlled data into downstream sinks: SQL queries, shell
commands, HTML templates, LDAP filters, XML parsers. The intent is perimeter
defence-in-depth — if a query string *looks like* an attack payload, reject it
before it can reach any of those sinks.

This is essentially the WAF (web application firewall) model, and it has real
appeal:

- It is cheap: substring matching over a string you already have.
- It catches naive automated scanners and low-effort attacks.
- It gives one choke point instead of trusting every downstream call site.
- For an organisation that cannot audit every sink, perimeter filtering feels
  like leverage.

The implementation is roughly 70 hardcoded substrings across six categories
(XSS, SQL, command injection, LDAP, XML, traversal), matched against the
lowercased query with three percent-decodings applied (`%20`, `%09`, `%0a`).

### Why it falls short

**1. Layer mismatch. This is the fundamental one.**

Injection is not a property of a string. It is a property of a string
*combined with how a sink interpolates it*. `--` is dangerous when
concatenated into SQL; it is completely inert in JSON, in HTML, in a
filesystem path, or in a parameterised query. A URL parser sits at the
transport layer and cannot know which sink — if any — the value reaches. So it
must guess, and it guesses pessimistically.

A parameterised query makes `--` harmless. A naive string-concatenated query
makes a thousand *other* strings harmful. The check helps neither case.

**2. The error costs point the wrong way.**

The blocklist is simultaneously too tight and too loose.

Too tight — all of these legitimate URLs are rejected under `policy="strict"`:

| Query | Pattern that fires |
|---|---|
| `?range=2024-01--2024-02` | `--` (SQL comment) |
| `?q=powershell` | `powershell` |
| `?file=/bin/bash` | `/bin/` |
| `?q=sleep(1)` | `sleep(` |
| `?tpl=/*comment*/` | `/*`, `*/` |
| `?q=src=x` | `src=` |
| `?next=a--b` | `--` |

Date ranges, kebab-case slugs, documentation search, package paths, and
performance tooling are all ordinary traffic.

Too loose — the check decodes only `%20`, `%09` and `%0a` before matching, so
`%2d%2d`, `%0c`, `%0b`, double-encoding, inline comment splitting (`/**/`),
case and whitespace variants, and Unicode homoglyphs all pass straight
through.

The combination is the worst possible trade: **it blocks the honest and not
the malicious.** An attacker adapts in seconds; a user with a date range
cannot.

**3. Unbounded maintenance surface.**

A signature list is an arms race. WAF vendors employ teams and ship rule
updates continuously. A library that releases every few months, with the
patterns hardcoded as Python lists, cannot keep pace — and every pattern added
to catch a bypass risks new false positives.

**4. False confidence, which can be security-negative.**

This is the most serious concern. A developer who sees "query injection
detection ✓" in a feature matrix may reasonably conclude that the URL layer
has handled injection, and be *less* rigorous about parameterised queries and
output encoding at the sink — displacing the only defence that actually works.
A check that cannot be relied upon adds a decision point without removing one.

**5. No per-parameter scoping.**

`has_query_injection()` matches against the whole concatenated query string,
so patterns can straddle a parameter boundary (`?a=x&&b=y` matches `&&`) and
all per-value context is lost.

**6. Its placement inverts the usual risk gradient.**

"Stricter" should mean "more likely to reject an attack". Here it means "more
likely to reject *your users*". The security-conscious developer who reaches
for `policy="strict"` — exactly the person this library should serve best — is
the one who gets broken. Meanwhile `balanced` (the default) disables the check
entirely, so most users never receive the protection its presence implies.

### If this is revisited

Demote it to a non-blocking **informational** `SecurityFinding` that callers
can log or alert on, rather than an exception. That keeps whatever signal
exists, removes the breakage, and states honestly that it is a hint rather
than a control.

The infrastructure for this now exists: as of 0.7.0, `validate_url_security()`
raises only on `critical`/`major` severities and returns lower severities as
advisory findings (see `BLOCKING_SEVERITIES` in `_security/__init__.py`).

---

## `has_suspicious_punycode()`

### The idea

Homograph and IDN spoofing. `аpple.com` written with a Cyrillic `а` renders
identically to `apple.com` in most fonts. Punycode (`xn--`) is how such domains
are encoded on the wire. The function tries to flag domains that are visually
confusable with legitimate brands, i.e. likely phishing.

**Note:** the function is currently **dead code**. It is defined and
re-exported but never called by `collect_security_findings()`, so it does not
affect `parse_url()` today.

### Why it falls short

**The structural error: confusability is a relation, not a property.**

You cannot meaningfully say "this domain is confusable". You can only say "this
domain is confusable *with that one*". Real defences — Chrome's IDN display
policy, Unicode UTS #39 — compute a skeleton (normalised) form and compare it
against a set of protected or previously-visited domains, plus script-mixing
rules within a label. Forcing this into a unary predicate is why the
implementation degenerates into arbitrary substring rules.

Concretely, per sub-heuristic:

**`confusable_pairs = ["rn", "vv", "cl", "l1", "0o"]`** — the idea is that `rn`
renders like `m`, `vv` like `w`, `cl` like `d`. So `rnicrosoft.com` looks like
`microsoft.com`.

Two problems. First, it is **not gated on punycode or non-ASCII at all** —
unlike the `suspicious_tlds` check immediately above it, which *is* correctly
gated. So it applies to every domain:

| Domain | Flagged | Because |
|---|---|---|
| `cloudflare.com` | yes | `cl` |
| `klarna.com` | yes | `rn` |
| `oracle.com` | yes | `cl` |
| `clickup.com` | yes | `cl` |

(also `journal`, `learn`, `modern`, `intern`, `corner`, …)

Second, even correctly gated, `rn` only means anything *relative to a specific
target brand*. In isolation it carries no signal at all.

**`domain.count("-") > 2`** — the idea is that phishing domains stuff hyphens
(`secure-login-paypal-verify.com`). But plenty of legitimate domains use three
or more hyphens; `my-cool-new-site.com` is flagged. It is a weak prior applied
without brand context.

**`common_brands`** (paypal, google, amazon, … plus generic words `bank`,
`secure`, `login`, `account`, `verify`) — this is the least broken part,
because it *is* gated on `has_non_ascii`. But 15 hardcoded brands out of the
millions that get phished is arbitrary, and the generic entries mean a
legitimate non-ASCII domain containing "bank" — a German, Swedish or Turkish
bank's IDN, say — is flagged.

**`suspicious_tlds`** gated on `is_punycode` — structurally sound. TLD
reputation is a weak and shifting signal, and it penalises legitimate users of
cheap TLDs, but the check is at least correctly scoped.

### The disciplined version already exists

`has_mixed_scripts()` detects script *mixing within a host* — a genuine unary
property, and a real UTS #39 signal. It is wired up and enforced under every
built-in policy. The library already has the defensible homograph check;
`has_suspicious_punycode()` is the undisciplined sibling.

### If this is revisited

Either delete it, or rebuild it as a relation: compute a UTS #39 skeleton and
compare against a caller-supplied set of protected domains. The
`confusable_pairs` and hyphen-count rules should not survive in any form.

---

## Summary

| | `has_query_injection` | `has_suspicious_punycode` |
|---|---|---|
| Currently reachable | Yes, under `policy="strict"` only | **No — dead code** |
| Core problem | Wrong layer: cannot see the sink | Confusability is a relation, not a property |
| False positives | Yes, on ordinary traffic | Yes, on major real domains |
| Bypassable | Trivially | n/a (not reachable) |
| Suggested direction | Demote to advisory finding | Delete, or rebuild against protected-domain set |

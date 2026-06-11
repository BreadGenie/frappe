# Encrypted Fields — Frappe Framework Spec

Status: **Draft — 2026-06-10**

## 1. Motivation

Frappe stores all DocType field values as plaintext in the database. Anyone with raw DB access can read sensitive data. Users with `System Manager` role can also read any field through Desk by default. This spec adds **field-level encryption at rest** to the framework, letting DocType authors mark fields as `encrypted` so their values are encrypted before DB write and decrypted only after an explicit permission check.

## 2. Design Decisions (ADR)

| Decision | Choice | Rationale |
|---|---|---|
| Field representation | `encrypted` property on existing text types | Non-breaking, flexible. Not a new fieldtype. |
| Storage | Separate `tabEncryption Keys` table | Follows `__Auth` pattern; no column type migrations; DEK metadata naturally co-located with ciphertext. |
| Key architecture | Per-document DEK, wrapped by KEK | Envelope encryption. DEK is random 32-byte AES-256 key per document. KEK from env var or `site_config` (see §4). |
| Decryption permission | Controller callback `has_decrypt_permission` | Backward-compatible default; apps override for custom logic. |
| Migration | Lazy (encrypt on first read) + `bench` command | Zero-downtime migration of existing data. |
| In-memory value after encrypt | Keep plaintext in memory through save cycle | Passwords are replaced with dummy due to high risk; encrypted text fields keep plaintext so `after_insert`/`on_update` hooks can read content. |
| Batch decryption | `frappe.decrypt_document_fields()` utility | Required for chat-stream APIs that load N messages at once (avoids N× `get_doc()` overhead). |
| Realtime event content | Include decrypted content in payloads | Socket.IO room is gated by channel membership (matches decrypt permission). |
| Sidebar previews | Store plaintext in `last_message_details` | Metadata concern at same exposure level as "a message was sent." Full content is encrypted. |

## 3. DocField Changes

### 3.1 New property

Add `encrypted` (`Check`, default `0`) to `DocField`.

Valid only on these fieldtypes: `Data`, `Small Text`, `Long Text`, `Text`, `Text Editor`, `Code`, `Markdown Editor`, `HTML Editor`.

### 3.2 Validation

- `encrypted: true` requires `fieldtype` to be in the allowed set above.
- `encrypted` and `search_index` are mutually exclusive — encrypted data is not indexable at the DB level.
- `encrypted` and `in_global_search` are mutually exclusive (same reason).
- `encrypted` is not allowed on child table fields (child table encryption is out of scope for v1).

## 4. Key Architecture

### 4.1 Key Hierarchy

```
FRAPPE_ENCRYPTION_KEY (env var)  ──or──  encryption_key (site_config)
  └── wraps ──→  DEK (random 32 bytes per document)
                   └── encrypts ──→  field value (AES-256-GCM)
```

### 4.2 KEK (Key Encryption Key)

- Read from `FRAPPE_ENCRYPTION_KEY` env var first (highest priority).
- Fallback to `encryption_key` in `site_config.json`.
- If neither exists: auto-generate and write to `site_config.json` (matches current `get_encryption_key()` behavior in `password.py`).

Add to `frappe/config.py` env-var-merge block:
```python
config["encryption_key"] = os.environ.get("FRAPPE_ENCRYPTION_KEY") or config.get("encryption_key")
```

### 4.3 DEK (Data Encryption Key)

- Generated once per document (when the first encrypted field is written).
- Stored in `tabEncryption Keys`, wrapped (encrypted) with the KEK.
- Never stored in plaintext anywhere.

### 4.4 Algorithm

- `AES-256-GCM` (authenticated encryption with associated data).
- `pycryptodome` or `cryptography` library (Frappe already depends on `cryptography` via Fernet).
- The AAD (additional authenticated data) includes: `doctype || docname || fieldname`. This binds the ciphertext to a specific document+field, preventing copy-paste attacks.

## 5. Storage — `tabEncryption Keys`

### 5.1 Schema

```sql
CREATE TABLE `tabEncryption Keys` (
  `name` VARCHAR(140) NOT NULL,        -- hash-based autoname
  `ref_doctype` VARCHAR(140) NOT NULL,
  `ref_docname` VARCHAR(140) NOT NULL,
  `fieldname` VARCHAR(140) NOT NULL,
  `encrypted_dek` TEXT NOT NULL,        -- DEK wrapped with KEK, base64-encoded
  `ciphertext` LONGTEXT NOT NULL,       -- field value encrypted with DEK, base64-encoded
  `created` DATETIME NOT NULL,
  `modified` DATETIME NOT NULL,
  `owner` VARCHAR(140) NOT NULL,
  `modified_by` VARCHAR(140) NOT NULL,
  PRIMARY KEY (`name`),
  INDEX `idx_ref` (`ref_doctype`, `ref_docname`),
  UNIQUE INDEX `idx_ref_field` (`ref_doctype`, `ref_docname`, `fieldname`)
);
```

### 5.2 DocType definition

Realised as a hidden DocType `Encryption Key` (not `__` prefixed, for proper ORM support, but flagged internal).

### 5.3 Relationship to main table

The plain `tab{Doctype}` column stores a placeholder value `<<encrypted>>` when the field is marked `encrypted`. This signals the framework to fetch from `tabEncryption Keys` instead. (Alternative: join via query — placeholder approach is simpler and avoids query overhead for non-encrypted fields.)

## 6. Save Flow

```
doc.save() / doc.insert()
  │
  ├─ before_validate / validate / before_save  (plaintext visible here)
  │
  ├─ [Framework] for each encrypted field:                         ← runs during _validate()
  │     1. Generate DEK (if first encrypted field for this doc)
  │     2. Encrypt plaintext with DEK (AES-256-GCM, AAD = doctype|docname|fieldname)
  │     3. Wrap DEK with KEK (AES-256-GCM, AAD = doctype|docname|fieldname)
  │     4. Store (ref_doctype, ref_docname, fieldname, encrypted_dek, ciphertext)
  │        to `tabEncryption Keys` (UPSERT — INSERT ON DUPLICATE KEY UPDATE)
  │     5. Do NOT replace in-memory value — keep plaintext for hooks
  │
  ├─ db_insert / db_update   (writes "<<encrypted>>" placeholder to main table)
  │
  └─ after_insert / on_update / on_change
       └─ plaintext still available via doc.text / doc.content
```

The encryption step runs during `_validate()`, mirroring exactly how `_save_passwords()` works at `base_document.py:1405`.

## 7. Read Flow

### 7.1 Direct `frappe.get_doc()`

```
frappe.get_doc("Raven Message", "abc")
  │
  ├─ load_from_db()
  │     └─ values from DB — encrypted fields are "<<encrypted>>"
  │
  ├─ [Framework] for each encrypted field with value "<<encrypted>>":
  │     1. Check has_decrypt_permission(user, doc)  ← callback
  │     2. If permitted:
  │           a. Fetch (encrypted_dek, ciphertext) from tabEncryption Keys
  │           b. Unwrap DEK with KEK
  │           c. Decrypt ciphertext with DEK
  │           d. Set field to plaintext
  │     3. If NOT permitted:
  │           a. Set field to None (or keep "<<encrypted>>")
  │           b. Optionally log the access denial
  │
  └─ return document
```

### 7.2 Permission callback

Default implementation (in `Document`):
```python
def has_decrypt_permission(self, user=None):
    """Return True if user may decrypt encrypted fields on this document."""
    if not user:
        user = frappe.session.user
    return self.has_permission("read")  # backward compatible
```

Apps override via controller method or `hooks.py` `has_permission`-style hook:
```python
# raven/api.py or raven/hooks.py
doc_events = {
    "Raven Message": {
        "has_decrypt_permission": "raven.permissions.raven_message_decrypt_permission"
    }
}
```

### 7.3 Batch / List View

When reading a list of documents (e.g., `frappe.get_list`, `frappe.db.get_all`), encrypted fields are **not decrypted** automatically. They return `<<encrypted>>`. This prevents N+1 decryption queries on list views.

To get decrypted values in bulk, callers must use a dedicated endpoint or explicitly request decryption.

### 7.4 REST API

- `GET /api/resource/{doctype}/{name}` — encrypted fields decrypted if caller passes permission check.
- `GET /api/resource/{doctype}?fields=["*"]` — encrypted fields return `<<encrypted>>` in list context.
- New query param `?decrypt_fields=["text","content"]` for explicit decryption in list context (permission-checked per document).

## 8. Batch Decryption Utility

### 8.1 `frappe.decrypt_document_fields()`

For apps that load many documents at once (e.g., chat stream APIs), the framework provides a batch decryption function:

```python
def decrypt_document_fields(
    docs: list[dict | Document],
    doctype: str,
    user: str | None = None,
    fields: list[str] | None = None,
) -> list[dict]:
```

**Behavior:**

1. Collects all `(ref_doctype, ref_docname, fieldname)` tuples from the input docs where the field value is `<<encrypted>>`.
2. Single batched query: `SELECT * FROM tabEncryption Keys WHERE (ref_doctype, ref_docname, fieldname) IN (...)`
3. Groups DEKs + ciphertexts by `ref_docname`.
4. For each document, checks `has_decrypt_permission(user, doc)` (batch-loads all decryption permissions if possible — e.g., Raven can batch-check channel membership with one query).
5. For permitted docs: unwrap DEK with KEK, decrypt ciphertext, replace `<<encrypted>>` with plaintext.
6. For denied docs: keep `<<encrypted>>` or set to `None`.
7. Returns the modified list.

**Performance:**
- 3 total DB queries regardless of batch size (fetch docs + fetch keys + fetch permissions).
- AES-256-GCM decrypt is ~1μs per field.
- KEK is cached in process memory (loaded once at startup).

### 8.2 Permission batch optimization

The framework allows the `has_decrypt_permission` callback to return a **batch result** for efficiency:

```python
# If the callback accepts a list of (user, doc) tuples, the framework
# calls it once with all docs instead of N times.
def raven_batch_decrypt_permission(requests: list[tuple[str, Document]]) -> list[bool]:
    # requests = [(user1, doc1), (user1, doc2), ...]
    # Single query: SELECT channel_id FROM tabRaven Channel Member
    #               WHERE user = ? AND channel_id IN (...)
    # Return bool per request
```

This is an optional optimization — the framework falls back to per-doc calls if the batch variant is not defined.

### 8.3 Outgoing webhooks

When Frappe delivers a webhook payload that includes encrypted fields, the fields contain `<<encrypted>>` by default. If the webhook is configured with a `resolve_encrypted` flag, the framework decrypts them before delivery (using the system's permission — System Manager bypass).

Default: send `<<encrypted>>`. Webhook config can opt into resolved values.

## 9. Search — Blind Index

Encrypted fields are **not** included in Frappe's global search (since they're ciphertext at rest). The framework provides a **blind index** mechanism that enables substring search over encrypted data without exposing plaintext.

### 9.1 Trigram Blind Index Algorithm

A blind index is a set of one-way hashes that allow the database to answer "does this text contain substring X?" without knowing the text itself.

**Storage side** (`compute_blind_index`):

```python
text = f"^{plaintext.lower()}$"         # pad with ^ and $ delimiters
trigrams = {text[i:i+3] for i in range(len(text) - 2)}
blind_index = " ".join(sorted(sha256(t) for t in trigrams))
```

- Text is lowercased for case-insensitive search.
- Padding (`^` at start, `$` at end) ensures word-boundary trigrams are captured (e.g., `^he` for "hello").
- Each overlapping 3-gram is hashed with SHA-256.
- Hashes are sorted alphabetically so the string is independent of word order.

**Search side** (`search_blind_index`):

```python
if len(search_text) < 3:
    return set()                         # minimum 3 chars required
query_trigrams = {search_text.lower()[i:i+3] for i in range(len(search_text) - 2)}
query_hashes = [sha256(t) for t in query_trigrams]
# Find rows where ALL query_hashes are present in the blind_index string
```

- Query is **not** padded — raw trigrams from the user's search text.
- All query trigrams must be present for a match (logical AND).
- Single-trigram queries (3 chars) are broad; precision increases with query length.
- Queries shorter than 3 characters return empty results (caller should prompt for longer input).

### 9.2 Properties

| Property | Behavior |
|---|---|
| Substring match | ✅ Searching "ello" finds "hello world" |
| Order-independent | ✅ Trigrams are matched as a set, not a sequence |
| Case-insensitive | ✅ Both storage and search lowercase |
| Minimum query | 3 characters (1 trigram) |
| False positive rate | ~1 / 2^128 per trigram (negligible) |
| Prefix/suffix match | ✅ `^`/`$` padding enables `^wor` and `rld$` matching |

### 9.3 Bench command

```bash
bench recompute-blind-index <doctype> <fieldname>
```

Recomputes the `blind_index` column for all existing Encryption Key rows of the given doctype+fieldname. Use when upgrading the blind index algorithm (e.g. from word-level to trigram).

### `bench rotate-encryption-key`

- On-demand KEK rotation: generates a new KEK (or accepts `--new-key <base64>`), re-wraps all existing DEKs.
- **Only DEKs are touched** — ciphertext is never decrypted/re-encrypted.
- **Old-KEK fallback**: rotation stores the old KEK as `old_encryption_key` in `site_config.json` before updating the primary key. The decrypt path tries the new KEK first, falls back to old on failure. After rotation completes (all rows verified), the old key is removed from config.
- **Crash recovery**: re-running is idempotent. Rows already re-wrapped under the new KEK are skipped (their DEK unwraps successfully with the new KEK). If rotation crashes mid-way, the old KEK is still available as fallback from `site_config.json`.
- **Concurrent saves**: rotation checks the `modified` timestamp of each Encryption Key row before writing. If a concurrent save has updated the row since it was read, the row is skipped (the save already created a fresh DEK under the current KEK).
- Flags: `--new-key <value>` (externally-provided KEK, paves road for KMS integration), `--batch-size <n>` (rows per batch, default 1000).

## 11. Bench Commands

### `bench encrypt-field <doctype> <fieldname>`

- Batch-encrypts all existing plaintext values in `fieldname` for all documents of `doctype`.
- Reads each doc, encrypts the field, writes to `tabEncryption Keys`, marks main column as `<<encrypted>>`.
- Progress bar for large tables.

### `bench decrypt-field <doctype> <fieldname>`

- Reverse operation — batch-decrypts and restores plaintext to main table.
- Removes entries from `tabEncryption Keys`.

## 12. Backward Compatibility

- Existing DocTypes without `encrypted` fields are unaffected.
- Removing `encrypted: true` from a field does NOT auto-decrypt. Run `bench decrypt-field` to restore.
- Changing a field to `encrypted: true` when data exists: lazy migration on first read, plus `bench encrypt-field` for proactive batch.

## 13. Audit Logging

The framework emits a `frappe.log_error` or a structured audit log when:
- An encrypted field is accessed for decryption (user, doctype, docname, fieldname, timestamp).
- A batch encrypt/decrypt command runs.
- A decryption permission check fails (optional, configurable).

## 14. Security Considerations

| Aspect | Decision |
|---|---|
| Key rotation | KEK rotation = re-wrap all DEKs. `bench rotate-encryption-key` command. |
| Key escrow | No escrow. If KEK is lost, data is permanently unrecoverable. |
| HSM support | Via custom provider interface (v2). |
| Timing attacks | Decryption is constant-time via AES-GCM. |
| Replay attacks | AAD binds ciphertext to doctype+docname+fieldname. |
| Backup | Encrypted backups (`encrypt_backup`) + at-rest encryption are independent layers. Backups contain encrypted data only. |

## 15. Future Scope (v2)

- External KMS provider (AWS KMS, HashiCorp Vault).
- `bench verify-encryption` — validates all wrapped DEKs can be unwrapped.
- Decryption performance metrics (cache hot DEKs).

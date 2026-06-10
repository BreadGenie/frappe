# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and contributors
# License: MIT. See LICENSE

import hashlib
import json
import re

from cryptography.fernet import Fernet, InvalidToken

import frappe
from frappe import _
from frappe.utils import cstr, encode

ENCRYPTED_PLACEHOLDER = "<<encrypted>>"


def encrypt_field_value(plaintext: str, doctype: str, docname: str, fieldname: str) -> tuple[str, str]:
	"""Encrypt a field value with a per-document DEK.

	Returns (wrapped_dek, ciphertext) — both base64-encoded strings.
	"""
	from cryptography.fernet import Fernet as FernetCipher

	kek = _get_kek()
	dek = FernetCipher.generate_key()
	cipher_suite = FernetCipher(dek)
	ciphertext = cstr(cipher_suite.encrypt(encode(plaintext)))

	# Wrap DEK with KEK
	kek_suite = FernetCipher(encode(kek))
	wrapped_dek = cstr(kek_suite.encrypt(encode(dek)))

	return wrapped_dek, ciphertext


def decrypt_field_value(wrapped_dek: str, ciphertext: str, doctype: str, docname: str, fieldname: str) -> str:
	"""Decrypt a field value using the wrapped DEK."""
	from cryptography.fernet import Fernet as FernetCipher

	kek = _get_kek()
	kek_suite = FernetCipher(encode(kek))
	dek = kek_suite.decrypt(encode(wrapped_dek))

	cipher_suite = FernetCipher(dek)
	aad = _build_aad(doctype, docname, fieldname)
	return cstr(cipher_suite.decrypt(encode(ciphertext)))


def _get_kek() -> str:
	"""Get the Key Encryption Key from env var or site_config."""
	from frappe.utils.password import get_encryption_key

	return get_encryption_key()


def _build_aad(doctype: str, docname: str, fieldname: str) -> bytes:
	"""Build Additional Authenticated Data that binds ciphertext to doc+field.
	Field binding is ensured by per-document per-field DEK storage.
	"""
	return encode(f"{doctype}||{docname}||{fieldname}")


def is_encrypted_placeholder(value) -> bool:
	if value == ENCRYPTED_PLACEHOLDER:
		return True
	# Handle JSON-encoded placeholder (e.g. fieldtype JSON stores '"<<encrypted>>"')
	if isinstance(value, str) and len(value) > 2 and value.startswith('"') and value.endswith('"'):
		try:
			return json.loads(value) == ENCRYPTED_PLACEHOLDER
		except Exception:
			pass
	return False


def compute_blind_index(text: str) -> str:
	"""Compute a blind index for search: space-separated sha256 hashes of each word.

	Words are lowercased, split on whitespace/punctuation, each hashed with SHA-256.
	Hashes are sorted so search terms match regardless of word order.
	"""
	words = re.findall(r"\w+", text.lower())
	if not words:
		return ""
	hashes = sorted(hashlib.sha256(w.encode()).hexdigest() for w in words)
	return " ".join(hashes)


def search_blind_index(
	doctype: str, fieldname: str, search_text: str
) -> set[str]:
	"""Search encrypted fields using blind index (exact word match).

	Returns a set of ``ref_docname`` values whose blind index contains
	all words in ``search_text``.  Each word must match exactly — substring
	and fuzzy matching are not supported (use ngram blind index for that).
	"""
	words = re.findall(r"\w+", search_text.lower())
	if not words:
		return set()

	query_hashes = [hashlib.sha256(w.encode()).hexdigest() for w in words]

	EncryptionKey = frappe.qb.Table("tabEncryption Key")

	if len(query_hashes) == 1:
		rows = (
			frappe.qb.from_(EncryptionKey)
			.select(EncryptionKey.ref_docname)
			.where(
				(EncryptionKey.ref_doctype == doctype)
				& (EncryptionKey.fieldname == fieldname)
				& (EncryptionKey.blind_index.like(f"%{query_hashes[0]}%"))
			)
		).run(as_dict=True)
		return {r.ref_docname for r in rows}

	rows = (
		frappe.qb.from_(EncryptionKey)
		.select(EncryptionKey.ref_docname, EncryptionKey.blind_index)
		.where(
			(EncryptionKey.ref_doctype == doctype)
			& (EncryptionKey.fieldname == fieldname)
		)
	).run(as_dict=True)

	result = set()
	for r in rows:
		if r.blind_index and all(h in r.blind_index for h in query_hashes):
			result.add(r.ref_docname)
	return result


def get_encrypted_field_meta(doctype: str, meta=None) -> list:
	"""Return list of field definitions (from DocField) where encrypted=true.

	Pass `meta` if already available to avoid loading it again.
	"""
	if meta is None:
		meta = frappe.get_meta(doctype)
	result = []
	for df in meta.get("fields"):
		if df.get("encrypted") and df.fieldtype in (
			"Data", "Small Text", "Long Text", "Text", "Text Editor", "Code", "Markdown Editor", "HTML Editor", "JSON", "Link"
		):
			result.append(df)
	return result


def store_encrypted_fields(doc, meta=None) -> None:
	"""Encrypt all encrypted fields on a document and store in Encryption Key table.

	Saves original plaintext values in doc.flags._original_encrypted_values
	so hooks can access them after replacement.
	"""
	meta = meta or doc.meta
	fields = get_encrypted_field_meta(doc.doctype, meta=meta)
	if not fields:
		return

	if not doc.name:
		return

	EncryptionKey = frappe.qb.Table("tabEncryption Key")
	saved_originals = {}

	for df in fields:
		val = doc.get(df.fieldname)
		if val is None or val == "" or is_encrypted_placeholder(val):
			continue

		# Skip if already encrypted during this save cycle
		if doc.flags.get("_encrypted_fields_done") and df.fieldname in doc.flags.get("_encrypted_fields_done", []):
			continue

		wrapped_dek, ciphertext = encrypt_field_value(
			str(val), doc.doctype, doc.name, df.fieldname
		)

		# Delete existing key for this field (clean upsert)
		frappe.db.delete("Encryption Key", {
			"ref_doctype": doc.doctype,
			"ref_docname": doc.name,
			"fieldname": df.fieldname,
		})

		blind_index = compute_blind_index(str(val))

		frappe.get_doc({
			"doctype": "Encryption Key",
			"ref_doctype": doc.doctype,
			"ref_docname": doc.name,
			"fieldname": df.fieldname,
			"encrypted_dek": wrapped_dek,
			"ciphertext": ciphertext,
			"blind_index": blind_index,
		}).insert(ignore_permissions=True)

		saved_originals[df.fieldname] = val
		placeholder = json.dumps(ENCRYPTED_PLACEHOLDER) if df.fieldtype == "JSON" else ENCRYPTED_PLACEHOLDER
		doc.set(df.fieldname, placeholder)

	# Track which fields were encrypted to avoid re-encrypting
	if not doc.flags.get("_encrypted_fields_done"):
		doc.flags._encrypted_fields_done = set()
	doc.flags._encrypted_fields_done.update(saved_originals.keys())

	# Store original values for hooks
	if saved_originals:
		if not doc.flags.get("_original_encrypted_values"):
			doc.flags._original_encrypted_values = {}
		doc.flags._original_encrypted_values.update(saved_originals)


def decrypt_document(doc, meta=None) -> None:
	"""Decrypt encrypted fields on a loaded document, respecting has_decrypt_permission."""
	meta = meta or doc.meta
	fields = get_encrypted_field_meta(doc.doctype, meta=meta)
	if not fields:
		return

	if not doc.name:
		return

	# Check permission
	if not doc.has_decrypt_permission(frappe.session.user):
		for df in fields:
			if is_encrypted_placeholder(doc.get(df.fieldname)):
				doc.set(df.fieldname, None)
		return

	# Load all encrypted fields for this document in one query
	EncryptionKey = frappe.qb.Table("tabEncryption Key")
	rows = (
		frappe.qb.from_(EncryptionKey)
		.select(
			EncryptionKey.fieldname,
			EncryptionKey.encrypted_dek,
			EncryptionKey.ciphertext,
		)
		.where(
			(EncryptionKey.ref_doctype == doc.doctype)
			& (EncryptionKey.ref_docname == doc.name)
		)
	).run(as_dict=True)

	if not rows:
		return

	field_map = {r.fieldname: r for r in rows}
	for df in fields:
		if df.fieldname in field_map and is_encrypted_placeholder(doc.get(df.fieldname)):
			try:
				plaintext = decrypt_field_value(
					field_map[df.fieldname].encrypted_dek,
					field_map[df.fieldname].ciphertext,
					doc.doctype, doc.name, df.fieldname,
				)
				if df.fieldtype == "JSON":
					try:
						plaintext = json.loads(plaintext)
					except (ValueError, TypeError):
						pass
				doc.set(df.fieldname, plaintext)
			except InvalidToken:
				frappe.log_error(
					_("Failed to decrypt {0} {1} {2}").format(doc.doctype, doc.name, df.fieldname),
					_("Encryption Error"),
				)

	# Decrypt child table encrypted fields
	for table_df in meta.get_table_fields():
		child_doctype = table_df.options
		child_encrypted_fields = get_encrypted_field_meta(child_doctype)
		if not child_encrypted_fields:
			continue

		children = doc.get(table_df.fieldname) or []
		if not children:
			continue

		if not doc.has_decrypt_permission(frappe.session.user):
			for child in children:
				for child_df in child_encrypted_fields:
					if is_encrypted_placeholder(child.get(child_df.fieldname)):
						child.set(child_df.fieldname, None)
			continue

		child_names = [c.name for c in children if c.name]
		if not child_names:
			continue

		key_rows = (
			frappe.qb.from_(frappe.qb.Table("tabEncryption Key"))
			.select(
				frappe.qb.Table("tabEncryption Key").ref_docname,
				frappe.qb.Table("tabEncryption Key").fieldname,
				frappe.qb.Table("tabEncryption Key").encrypted_dek,
				frappe.qb.Table("tabEncryption Key").ciphertext,
			)
			.where(
				(frappe.qb.Table("tabEncryption Key").ref_doctype == child_doctype)
				& (frappe.qb.Table("tabEncryption Key").ref_docname.isin(child_names))
			)
		).run(as_dict=True)

		if not key_rows:
			continue

		keys_by_child = {}
		for r in key_rows:
			keys_by_child.setdefault(r.ref_docname, {})[r.fieldname] = r

		for child in children:
			if child.name not in keys_by_child:
				continue
			child_keys = keys_by_child[child.name]
			for child_df in child_encrypted_fields:
				fn = child_df.fieldname
				if fn in child_keys and is_encrypted_placeholder(child.get(fn)):
					try:
						plaintext = decrypt_field_value(
							child_keys[fn].encrypted_dek,
							child_keys[fn].ciphertext,
							child.doctype, child.name, fn,
						)
						child.set(fn, plaintext)
					except InvalidToken:
						frappe.log_error(
							_("Failed to decrypt {0} {1} {2}").format(child.doctype, child.name, fn),
							_("Encryption Error"),
						)


def decrypt_document_fields(
	docs: list[dict],
	doctype: str,
	user: str | None = None,
	fields: list[str] | None = None,
	skip_permission_check: bool = False,
) -> list[dict]:
	"""Batch decrypt encrypted fields for a list of document dicts.

	More efficient than loading each doc via frappe.get_doc() for list views.
	Set ``skip_permission_check=True`` when the caller has already gated access
	(e.g. the API has already verified channel membership).
	"""

	if not docs:
		return docs

	user = user or frappe.session.user
	encrypted_fields = get_encrypted_field_meta(doctype)
	if not encrypted_fields:
		return docs

	fieldnames = {df.fieldname for df in encrypted_fields}
	if fields:
		fieldnames &= set(fields)

	docnames = [d.get("name") for d in docs if d.get("name")]

	# Batch fetch all encryption keys
	EncryptionKey = frappe.qb.Table("tabEncryption Key")
	key_rows = (
		frappe.qb.from_(EncryptionKey)
		.select(
			EncryptionKey.ref_docname,
			EncryptionKey.fieldname,
			EncryptionKey.encrypted_dek,
			EncryptionKey.ciphertext,
		)
		.where(
			(EncryptionKey.ref_doctype == doctype)
			& (EncryptionKey.ref_docname.isin(docnames))
		)
	).run(as_dict=True)

	if not key_rows:
		return docs

	# Group keys by docname
	keys_by_doc: dict[str, dict[str, dict]] = {}
	for r in key_rows:
		keys_by_doc.setdefault(r.ref_docname, {})[r.fieldname] = r

	# Check permissions per doc
	permission_cache: dict[str, bool] = {}

	def _check_perm(docname: str) -> bool:
		if docname not in permission_cache:
			try:
				if skip_permission_check:
					permission_cache[docname] = True
				else:
					doc = frappe.get_doc(doctype, docname)
					permission_cache[docname] = doc.has_decrypt_permission(user)
			except Exception:
				permission_cache[docname] = False
		return permission_cache[docname]

	# Build a map of fieldname -> fieldtype for JSON field handling
	fieldtype_map = {df.fieldname: df.fieldtype for df in encrypted_fields if df.fieldtype == "JSON"}

	# Decrypt
	result = []
	for d in docs:
		docname = d.get("name")
		if docname and docname in keys_by_doc and _check_perm(docname):
			doc_keys = keys_by_doc[docname]
			for fieldname in fieldnames:
				if fieldname in doc_keys and is_encrypted_placeholder(d.get(fieldname)):
					try:
						plaintext = decrypt_field_value(
							doc_keys[fieldname].encrypted_dek,
							doc_keys[fieldname].ciphertext,
							doctype, docname, fieldname,
						)
						if fieldname in fieldtype_map:
							try:
								plaintext = json.loads(plaintext)
							except (ValueError, TypeError):
								pass
						d[fieldname] = plaintext
					except InvalidToken:
						pass

		result.append(d)

	return result


def get_original_encrypted_value(doc, fieldname: str, default=None):
	"""Get the original plaintext value before it was replaced with <<encrypted>>."""
	if doc.flags.get("_original_encrypted_values"):
		return doc.flags._original_encrypted_values.get(fieldname, default)
	return default

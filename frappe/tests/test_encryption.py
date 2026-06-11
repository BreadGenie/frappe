import hashlib

import frappe
from frappe.tests import IntegrationTestCase, UnitTestCase


class TestEncryptionUtils(UnitTestCase):
	"""Unit tests for encryption utility functions (no doctype needed)."""

	def test_encrypt_decrypt_roundtrip(self):
		from frappe.utils.encryption import decrypt_field_value, encrypt_field_value

		wrapped_dek, ciphertext = encrypt_field_value("hello", "TestDoc", "TEST001", "text")
		self.assertIsInstance(wrapped_dek, str)
		self.assertIsInstance(ciphertext, str)

		plaintext = decrypt_field_value(wrapped_dek, ciphertext, "TestDoc", "TEST001", "text")
		self.assertEqual(plaintext, "hello")

	def test_encrypt_decrypt_empty_string(self):
		from frappe.utils.encryption import decrypt_field_value, encrypt_field_value

		wrapped_dek, ciphertext = encrypt_field_value("", "TestDoc", "TEST002", "text")
		plaintext = decrypt_field_value(wrapped_dek, ciphertext, "TestDoc", "TEST002", "text")
		self.assertEqual(plaintext, "")

	def test_encrypt_decrypt_unicode(self):
		from frappe.utils.encryption import decrypt_field_value, encrypt_field_value

		text = "héllo wörld 🔐"
		wrapped_dek, ciphertext = encrypt_field_value(text, "TestDoc", "TEST003", "text")
		plaintext = decrypt_field_value(wrapped_dek, ciphertext, "TestDoc", "TEST003", "text")
		self.assertEqual(plaintext, text)

	def test_encrypt_decrypt_long_text(self):
		from frappe.utils.encryption import decrypt_field_value, encrypt_field_value

		text = "A" * 10000
		wrapped_dek, ciphertext = encrypt_field_value(text, "TestDoc", "TEST004", "text")
		plaintext = decrypt_field_value(wrapped_dek, ciphertext, "TestDoc", "TEST004", "text")
		self.assertEqual(plaintext, text)

	def test_encrypt_different_docs_different_ciphertext(self):
		from frappe.utils.encryption import encrypt_field_value

		_, c1 = encrypt_field_value("same", "DocA", "D001", "text")
		_, c2 = encrypt_field_value("same", "DocB", "D002", "text")
		self.assertNotEqual(c1, c2)

	def test_is_encrypted_placeholder(self):
		from frappe.utils.encryption import is_encrypted_placeholder

		self.assertTrue(is_encrypted_placeholder("<<encrypted>>"))
		self.assertFalse(is_encrypted_placeholder("plain text"))
		self.assertFalse(is_encrypted_placeholder(""))
		self.assertFalse(is_encrypted_placeholder(None))

	def test_get_encrypted_field_meta_none(self):
		from frappe.utils.encryption import get_encrypted_field_meta

		fields = get_encrypted_field_meta("DocType")
		self.assertEqual(fields, [])

	def test_get_original_encrypted_value(self):
		from frappe.utils.encryption import get_original_encrypted_value

		doc = frappe._dict(flags=frappe._dict())
		self.assertIsNone(get_original_encrypted_value(doc, "text"))

		doc.flags._original_encrypted_values = {"text": "original value"}
		self.assertEqual(get_original_encrypted_value(doc, "text"), "original value")
		self.assertIsNone(get_original_encrypted_value(doc, "other"))


class TestBlindIndex(UnitTestCase):
	"""Unit tests for ngram blind index computation and search."""

	def test_compute_blind_index_basic(self):
		from frappe.utils.encryption import compute_blind_index

		bi = compute_blind_index("hello")
		self.assertIsInstance(bi, str)
		# "hello" padded ^hello$ gives 5 trigrams → 5 * 64 + 4 spaces = 324
		parts = bi.split()
		self.assertEqual(len(parts), 5)  # ^he hel ell llo lo$

	def test_compute_blind_index_empty(self):
		from frappe.utils.encryption import compute_blind_index

		self.assertEqual(compute_blind_index(""), "")
		self.assertEqual(compute_blind_index("   "), "")
		# "!@#$" has 4 meaningful chars → produces trigrams
		self.assertNotEqual(compute_blind_index("!@#$"), "")

	def test_compute_blind_index_short(self):
		from frappe.utils.encryption import compute_blind_index

		bi = compute_blind_index("hi")
		# padded ^hi$ → 2 trigrams: ^hi hi$
		parts = bi.split()
		self.assertEqual(len(parts), 2)

	def test_compute_blind_index_multi_word(self):
		from frappe.utils.encryption import compute_blind_index

		bi = compute_blind_index("hello world")
		# padded ^hello world$ → trigrams: ^he hel ell llo "lo " "o w" " wo" wor orl rld ld$
		parts = bi.split()
		self.assertEqual(len(parts), 11)
		self.assertEqual(len(parts[0]), 64)

	def test_compute_blind_index_deterministic(self):
		from frappe.utils.encryption import compute_blind_index

		bi1 = compute_blind_index("hello world")
		bi2 = compute_blind_index("hello world")
		self.assertEqual(bi1, bi2)

	def test_compute_blind_index_order_matters(self):
		from frappe.utils.encryption import compute_blind_index

		# Trigram blind index is position-sensitive — word order changes trigrams
		bi1 = compute_blind_index("hello world")
		bi2 = compute_blind_index("world hello")
		self.assertNotEqual(bi1, bi2)

	def test_compute_blind_index_case_insensitive(self):
		from frappe.utils.encryption import compute_blind_index

		bi1 = compute_blind_index("Hello World")
		bi2 = compute_blind_index("hello world")
		self.assertEqual(bi1, bi2)

	def test_compute_blind_index_substring_relevance(self):
		from frappe.utils.encryption import compute_blind_index

		# "hello" and "hi" share no trigrams (h, he, i, etc. are 1-2 chars)
		# but "hello" and "hel" share trigram "hel"
		bi_hello = compute_blind_index("hello")
		bi_hel = compute_blind_index("hel")
		# bi_hel padded ^hel$ has trigrams: ^he hel el$ (3 trigrams)
		# bi_hello padded ^hello$ has trigrams: ^he hel ell llo lo$ (5 trigrams)
		# both should contain the hash of "hel"
		h_hel = hashlib.sha256(b"hel").hexdigest()
		self.assertIn(h_hel, bi_hello)
		self.assertIn(h_hel, bi_hel)


class TestEncryptionIntegration(IntegrationTestCase):
	"""Integration tests for the document save/load encryption cycle."""

	ENCRYPTED_FIELD = "description"
	TEST_DOCTYPE = "ToDo"

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		# Temporarily mark the description field as encrypted
		cls._enable_encryption_on_field()

	@classmethod
	def _enable_encryption_on_field(cls):
		field_name = cls.ENCRYPTED_FIELD
		doctype = cls.TEST_DOCTYPE
		docfield = frappe.db.get_value(
			"DocField",
			{"parent": doctype, "fieldname": field_name},
			["name", "fieldtype"],
			as_dict=True,
		)
		if not docfield:
			raise unittest.SkipTest(f"Field {field_name} not found on {doctype}")

		cls._docfield_name = docfield.name
		cls._original_fieldtype = docfield.fieldtype

		# Enable encrypted on the field
		frappe.db.set_value("DocField", docfield.name, "encrypted", 1)
		frappe.cache.delete_value("doctype_meta")
		frappe.clear_cache(doctype=doctype)

	@classmethod
	def tearDownClass(cls):
		# Restore original field state
		frappe.db.set_value("DocField", cls._docfield_name, "encrypted", 0)
		frappe.cache.delete_value("doctype_meta")
		frappe.clear_cache(doctype=cls.TEST_DOCTYPE)
		super().tearDownClass()

	def setUp(self):
		super().setUp()
		self._test_data = frappe.get_doc(
			{
				"doctype": self.TEST_DOCTYPE,
				"description": "test encrypted content",
				"allocated_to": frappe.session.user,
			}
		).insert()

	def tearDown(self):
		frappe.delete_doc(self.TEST_DOCTYPE, self._test_data.name, force=True)
		super().tearDown()

	def test_save_stores_placeholder_in_db(self):
		from frappe.utils.encryption import is_encrypted_placeholder

		db_value = frappe.db.get_value(self.TEST_DOCTYPE, self._test_data.name, self.ENCRYPTED_FIELD)
		self.assertTrue(is_encrypted_placeholder(db_value))

	def test_load_decrypts_placeholder_to_plaintext(self):
		doc = frappe.get_doc(self.TEST_DOCTYPE, self._test_data.name)
		self.assertEqual(doc.get(self.ENCRYPTED_FIELD), "test encrypted content")

	def test_encryption_key_created(self):
		key = frappe.db.exists(
			"Encryption Key",
			{
				"ref_doctype": self.TEST_DOCTYPE,
				"ref_docname": self._test_data.name,
				"fieldname": self.ENCRYPTED_FIELD,
			},
		)
		self.assertTrue(key)

	def test_get_all_shows_placeholder(self):
		from frappe.utils.encryption import is_encrypted_placeholder

		rows = frappe.get_all(self.TEST_DOCTYPE, filters={"name": self._test_data.name}, fields=["description"])
		self.assertTrue(len(rows) == 1)
		self.assertTrue(is_encrypted_placeholder(rows[0]["description"]))

	def test_re_save_does_not_double_encrypt(self):
		doc = frappe.get_doc(self.TEST_DOCTYPE, self._test_data.name)
		doc.description = "updated content"
		doc.save()

		from frappe.utils.encryption import is_encrypted_placeholder
		db_value = frappe.db.get_value(self.TEST_DOCTYPE, doc.name, self.ENCRYPTED_FIELD)
		self.assertTrue(is_encrypted_placeholder(db_value))

		loaded = frappe.get_doc(self.TEST_DOCTYPE, doc.name)
		self.assertEqual(loaded.description, "updated content")

	# Count of encryption keys should remain 1 (upsert, not duplicate)
		keys = frappe.get_all(
			"Encryption Key",
			filters={
				"ref_doctype": self.TEST_DOCTYPE,
				"ref_docname": doc.name,
				"fieldname": self.ENCRYPTED_FIELD,
			},
		)
		self.assertEqual(len(keys), 1)

	def test_decrypt_document_fields_batch(self):
		from frappe.utils.encryption import decrypt_document_fields

		# Create a second encrypted doc
		doc2 = frappe.get_doc(
			{
				"doctype": self.TEST_DOCTYPE,
				"description": "second secret",
				"allocated_to": frappe.session.user,
			}
		).insert()

		docs_data = frappe.get_all(
			self.TEST_DOCTYPE,
			filters={"name": ["in", [self._test_data.name, doc2.name]]},
			fields=["name", "description"],
		)

		decrypted = decrypt_document_fields(docs_data, self.TEST_DOCTYPE, user=frappe.session.user)

		for d in decrypted:
			if d.name == self._test_data.name:
				self.assertEqual(d["description"], "test encrypted content")
			elif d.name == doc2.name:
				self.assertEqual(d["description"], "second secret")

		frappe.delete_doc(self.TEST_DOCTYPE, doc2.name, force=True)

	def test_blind_index_stored_on_encrypt(self):
		from frappe.utils.encryption import is_encrypted_placeholder

		key = frappe.db.get_value(
			"Encryption Key",
			{
				"ref_doctype": self.TEST_DOCTYPE,
				"ref_docname": self._test_data.name,
				"fieldname": self.ENCRYPTED_FIELD,
			},
			"blind_index",
		)
		self.assertIsNotNone(key)
		self.assertNotEqual(key, "")
		# Should contain trigram hashes from "test encrypted content"
		# Pick one representative trigram per word
		import hashlib
		for tri in ["tes", "enc", "con"]:
			h = hashlib.sha256(tri.encode()).hexdigest()
			self.assertIn(h, key, f"Missing trigram hash for '{tri}'")

	def test_search_blind_index_substring(self):
		from frappe.utils.encryption import search_blind_index

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "encrypted")
		self.assertIn(self._test_data.name, results)

		# Substring of "encrypted" should also match
		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "crypt")
		self.assertIn(self._test_data.name, results)

		# Non-existent query
		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "zzz")
		self.assertNotIn(self._test_data.name, results)

	def test_search_blind_index_empty_query(self):
		from frappe.utils.encryption import search_blind_index

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "")
		self.assertEqual(results, set())

	def test_search_blind_index_short_query(self):
		from frappe.utils.encryption import search_blind_index

		# < 3 chars returns empty set
		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "xy")
		self.assertEqual(results, set())

	def test_search_blind_index_multi_word(self):
		from frappe.utils.encryption import search_blind_index

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "test encrypted")
		self.assertIn(self._test_data.name, results)

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "test nonexistent")
		self.assertNotIn(self._test_data.name, results)


class TestRestoreEncryptedPlaceholders(IntegrationTestCase):
	"""Tests for _restore_encrypted_placeholders on parent and child table encrypted fields."""

	PARENT_DOCTYPE = "ToDo"
	PARENT_FIELD = "description"
	CHILD_DOCTYPE = "DefaultValue"
	CHILD_FIELD = "defvalue"

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		cls._enable_encryption("ToDo", "description")
		cls._enable_encryption("DefaultValue", "defvalue")

	@classmethod
	def _enable_encryption(cls, doctype, fieldname):
		import unittest

		docfield = frappe.db.get_value(
			"DocField",
			{"parent": doctype, "fieldname": fieldname},
			["name", "fieldtype"],
			as_dict=True,
		)
		if not docfield:
			raise unittest.SkipTest(f"Field {fieldname} not found on {doctype}")

		# Set encrypted on the field (append to list for cleanup)
		frappe.db.set_value("DocField", docfield.name, "encrypted", 1)
		frappe.cache.delete_value("doctype_meta")
		frappe.clear_cache(doctype=doctype)

		if not hasattr(cls, "_encrypted_fields"):
			cls._encrypted_fields = []
		cls._encrypted_fields.append((doctype, docfield.name))

	@classmethod
	def tearDownClass(cls):
		for doctype, docfield_name in getattr(cls, "_encrypted_fields", []):
			frappe.db.set_value("DocField", docfield_name, "encrypted", 0)
			frappe.cache.delete_value("doctype_meta")
			frappe.clear_cache(doctype=doctype)
		super().tearDownClass()

	def setUp(self):
		super().setUp()

		# Parent test doc
		self._parent_doc = frappe.get_doc(
			{
				"doctype": self.PARENT_DOCTYPE,
				"description": "parent secret",
				"allocated_to": frappe.session.user,
			}
		).insert()

		# Child table test doc: add a DefaultValue child row to the current user
		self._user = frappe.get_doc("User", frappe.session.user)
		self._defaults_before = [d.as_dict() for d in self._user.get("defaults") or []]
		self._user.append("defaults", {
			"defkey": "test_encryption_key",
			"defvalue": "child secret value",
		})
		self._user.save()

	def tearDown(self):
		# Restore user defaults to pre-test state
		self._user = frappe.get_doc("User", frappe.session.user)
		self._user.set("defaults", self._defaults_before)
		self._user.save()

		frappe.delete_doc(self.PARENT_DOCTYPE, self._parent_doc.name, force=True)
		super().tearDown()

	def test_restore_placeholder_on_parent(self):
		from frappe.model.delete_doc import _restore_encrypted_placeholders
		from frappe.utils.encryption import is_encrypted_placeholder

		# Load doc — encrypted field is decrypted to plaintext
		doc = frappe.get_doc(self.PARENT_DOCTYPE, self._parent_doc.name)
		self.assertEqual(doc.get(self.PARENT_FIELD), "parent secret")
		self.assertFalse(is_encrypted_placeholder(doc.get(self.PARENT_FIELD)))

		# Restore placeholders
		_restore_encrypted_placeholders(doc)

		# Verify field is back to placeholder
		self.assertTrue(is_encrypted_placeholder(doc.get(self.PARENT_FIELD)))

		# Verify as_json() captures placeholder (what Deleted Document would store)
		import json
		data = json.loads(doc.as_json())
		self.assertTrue(is_encrypted_placeholder(data.get(self.PARENT_FIELD)))

	def test_restore_placeholder_on_child_table(self):
		from frappe.model.delete_doc import _restore_encrypted_placeholders
		from frappe.utils.encryption import is_encrypted_placeholder
		import json

		# Reload user — child field is decrypted to plaintext
		user = frappe.get_doc("User", frappe.session.user)
		defaults = user.get("defaults") or []
		child_row = [d for d in defaults if d.defkey == "test_encryption_key"]
		self.assertGreater(len(child_row), 0)
		self.assertEqual(child_row[0].defvalue, "child secret value")
		self.assertFalse(is_encrypted_placeholder(child_row[0].defvalue))

		# Restore placeholders
		_restore_encrypted_placeholders(user)

		# Verify child field is back to placeholder
		child_row = [d for d in (user.get("defaults") or []) if d.defkey == "test_encryption_key"]
		self.assertGreater(len(child_row), 0)
		self.assertTrue(is_encrypted_placeholder(child_row[0].defvalue))

		# Verify as_json() captures placeholder on child field
		data = json.loads(user.as_json())
		child_data = [d for d in data.get("defaults", []) if d.get("defkey") == "test_encryption_key"]
		self.assertGreater(len(child_data), 0)
		self.assertTrue(is_encrypted_placeholder(child_data[0].get("defvalue")))

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
	"""Unit tests for blind index computation and search."""

	def test_compute_blind_index_basic(self):
		from frappe.utils.encryption import compute_blind_index

		bi = compute_blind_index("hello")
		self.assertIsInstance(bi, str)
		self.assertEqual(len(bi), 64)  # sha256 hex is 64 chars

	def test_compute_blind_index_empty(self):
		from frappe.utils.encryption import compute_blind_index

		self.assertEqual(compute_blind_index(""), "")
		self.assertEqual(compute_blind_index("   "), "")
		self.assertEqual(compute_blind_index("!@#$"), "")

	def test_compute_blind_index_multi_word(self):
		from frappe.utils.encryption import compute_blind_index

		bi = compute_blind_index("hello world")
		# Should contain two hashes separated by space
		parts = bi.split()
		self.assertEqual(len(parts), 2)
		self.assertEqual(len(parts[0]), 64)
		self.assertEqual(len(parts[1]), 64)

	def test_compute_blind_index_sorted(self):
		from frappe.utils.encryption import compute_blind_index

		bi1 = compute_blind_index("hello world")
		bi2 = compute_blind_index("world hello")
		self.assertEqual(bi1, bi2)

	def test_compute_blind_index_case_insensitive(self):
		from frappe.utils.encryption import compute_blind_index

		bi1 = compute_blind_index("Hello World")
		bi2 = compute_blind_index("hello world")
		self.assertEqual(bi1, bi2)

	def test_compute_blind_index_deterministic(self):
		from frappe.utils.encryption import compute_blind_index

		bi1 = compute_blind_index("meeting at 3pm")
		bi2 = compute_blind_index("meeting at 3pm")
		self.assertEqual(bi1, bi2)

	def test_compute_blind_index_punctuation(self):
		from frappe.utils.encryption import compute_blind_index

		bi1 = compute_blind_index("hello, world!")
		bi2 = compute_blind_index("hello world")
		bi3 = compute_blind_index("hello-world")
		self.assertEqual(bi1, bi2)
		self.assertEqual(bi1, bi3)


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
		# Should contain hash of "test" and "encrypted" and "content"
		import hashlib

		for word in ["test", "encrypted", "content"]:
			h = hashlib.sha256(word.encode()).hexdigest()
			self.assertIn(h, key)

	def test_search_blind_index_exact_word(self):
		from frappe.utils.encryption import search_blind_index

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "encrypted")
		self.assertIn(self._test_data.name, results)

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "nonexistent")
		self.assertNotIn(self._test_data.name, results)

	def test_search_blind_index_empty_query(self):
		from frappe.utils.encryption import search_blind_index

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "")
		self.assertEqual(results, set())

	def test_search_blind_index_multi_word(self):
		from frappe.utils.encryption import search_blind_index

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "test encrypted")
		self.assertIn(self._test_data.name, results)

		results = search_blind_index(self.TEST_DOCTYPE, self.ENCRYPTED_FIELD, "test nonexistent")
		self.assertNotIn(self._test_data.name, results)

import test from "node:test";
import assert from "node:assert/strict";
import {
	encryptContent,
	encryptContentVerified,
	decryptContent,
	DecryptError,
	SelfCheckError,
	MIN_ITERATIONS,
	MAX_ITERATIONS,
} from "../src/crypto.ts";

test("encryptContent and decryptContent round-trip", async () => {
	const plaintext = "# Secret Journal\n\nThis is private information.";
	const password = "correct-horse-battery-staple";
	const payload = await encryptContent(plaintext, password, "vault", 100000);

	assert.equal(payload.v, 1);
	assert.equal(payload.alg, "AES-GCM");
	assert.equal(payload.kdf, "PBKDF2");
	assert.equal(payload.hash, "SHA-256");
	assert.equal(payload.scope, "vault");

	const decrypted = await decryptContent(payload, password);
	assert.equal(decrypted, plaintext);
});

test("decryptContent throws DecryptError on wrong password", async () => {
	const plaintext = "Top secret";
	const payload = await encryptContent(plaintext, "password123", "note", 100000);

	await assert.rejects(
		async () => {
			await decryptContent(payload, "wrongpassword");
		},
		DecryptError
	);
});

test("encryptContentVerified verifies content matches before returning", async () => {
	const plaintext = "Verified secret notes";
	const payload = await encryptContentVerified(plaintext, "validpassword", "vault", 100000);
	const decrypted = await decryptContent(payload, "validpassword");
	assert.equal(decrypted, plaintext);
});

test("decryptContent rejects corrupted or tampered ciphertext", async () => {
	const payload = await encryptContent("Valid text", "password123", "vault", 100000);
	// Corrupt ciphertext
	const corrupted = { ...payload, ct: "YWJjZGVmZ2hpams=" };

	await assert.rejects(
		async () => {
			await decryptContent(corrupted, "password123");
		},
		DecryptError
	);
});

test("decryptContent rejects out-of-range iterations", async () => {
	const payload = await encryptContent("Valid text", "password123", "vault", 100000);
	const tooFew = { ...payload, iterations: MIN_ITERATIONS - 1 };
	const tooMany = { ...payload, iterations: MAX_ITERATIONS + 1 };

	await assert.rejects(
		async () => {
			await decryptContent(tooFew, "password123");
		},
		DecryptError
	);

	await assert.rejects(
		async () => {
			await decryptContent(tooMany, "password123");
		},
		DecryptError
	);
});

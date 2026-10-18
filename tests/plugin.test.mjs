import test from "node:test";
import assert from "node:assert/strict";
import LockyPlugin from "../src/main.ts";
import { isLocked, buildLockedNote } from "../src/format.ts";
import { encryptContent } from "../src/crypto.ts";

class MockFile {
	constructor(path, content) {
		this.path = path;
		this.name = path.split("/").pop();
		this.basename = this.name.replace(/\.[^/.]+$/, "");
		this.extension = "md";
		this.content = content;
	}
}

class MockFolder {
	constructor(path) {
		this.path = path;
		this.name = path.split("/").pop() || "/";
	}
	isRoot() {
		return this.path === "" || this.path === "/";
	}
}

class TestLockyPlugin extends LockyPlugin {
	constructor(app) {
		super(app, { id: "locky", name: "Locky" });
		this.persistedData = null;
		this.suppliedPassword = null;
		this.confirmResponse = true;
	}

	async loadData() {
		return this.persistedData;
	}

	async saveData(data) {
		this.persistedData = data;
	}

	promptPassword() {
		return Promise.resolve(this.suppliedPassword);
	}

	confirmBulk() {
		return Promise.resolve(this.confirmResponse);
	}

	// Expose internals for verification in tests
	getUnlockedMap() {
		return this.unlocked;
	}

	getLedger() {
		return this.persistedData?.ledger ?? [];
	}

	triggerSweep() {
		return this.sweep();
	}
}

function createMockApp(filesMap) {
	const files = new Map();
	for (const [path, content] of Object.entries(filesMap)) {
		files.set(path, new MockFile(path, content));
	}

	const app = {
		vault: {
			read: async (file) => files.get(file.path)?.content ?? "",
			modify: async (file, content) => {
				const f = files.get(file.path);
				if (f) f.content = content;
			},
			process: async (file, fn) => {
				const f = files.get(file.path);
				if (f) {
					f.content = fn(f.content);
				}
				return f?.content;
			},
			getMarkdownFiles: () => Array.from(files.values()),
			getAbstractFileByPath: (path) => files.get(path) ?? null,
			getRoot: () => new MockFolder("/"),
			on: () => ({}),
		},
		workspace: {
			getActiveFile: () => null,
			getLeavesOfType: () => [],
			on: () => ({}),
			onLayoutReady: (cb) => cb(),
		},
	};
	return { app, files };
}

test("permanentlyDecryptNote on locked note undoes encryption permanently", async () => {
	const initialPlaintext = "# Important Notes\n\nSecret contents here.";
	const password = "myVaultPassword123";
	const payload = await encryptContent(initialPlaintext, password, "vault", 100000);
	const lockedContent = buildLockedNote(payload);

	const { app, files } = createMockApp({
		"secret.md": lockedContent,
	});

	const plugin = new TestLockyPlugin(app);
	plugin.suppliedPassword = password;
	plugin.settings.iterations = 100000;

	const targetFile = files.get("secret.md");
	assert.ok(isLocked(targetFile.content));

	// Permanently decrypt the note
	await plugin.permanentlyDecryptNote(targetFile);

	// 1. Content on disk should now be plain markdown
	assert.equal(targetFile.content, initialPlaintext);
	assert.equal(isLocked(targetFile.content), false);

	// 2. Note must NOT be tracked in unlocked map
	assert.equal(plugin.getUnlockedMap().has("secret.md"), false);

	// 3. Note must NOT be in persisted crash recovery ledger
	assert.equal(plugin.getLedger().length, 0);

	// 4. Inactivity sweep should NOT re-lock the note
	await plugin.triggerSweep();
	assert.equal(targetFile.content, initialPlaintext);
	assert.equal(isLocked(targetFile.content), false);
});

test("permanentlyDecryptNote on already unlocked note removes tracking so it is not re-locked", async () => {
	const initialPlaintext = "# Confidential\n\nUnlocked plaintext currently in memory.";
	const password = "myVaultPassword123";
	const payload = await encryptContent(initialPlaintext, password, "vault", 100000);
	const lockedContent = buildLockedNote(payload);

	const { app, files } = createMockApp({
		"doc.md": lockedContent,
	});

	const plugin = new TestLockyPlugin(app);
	plugin.suppliedPassword = password;
	plugin.confirmResponse = true;

	const targetFile = files.get("doc.md");

	// Step 1: Unlock note normally (this puts it into unlocked map)
	await plugin.unlockNote(targetFile);
	assert.equal(targetFile.content, initialPlaintext);
	assert.ok(plugin.getUnlockedMap().has("doc.md"));
	assert.equal(plugin.getLedger().length, 1);

	// Step 2: Permanently decrypt note
	await plugin.permanentlyDecryptNote(targetFile);

	// Note should now be untracked
	assert.equal(plugin.getUnlockedMap().has("doc.md"), false);
	assert.equal(plugin.getLedger().length, 0);
	assert.equal(targetFile.content, initialPlaintext);

	// Step 3: Trigger sweep (auto-lock). It must NOT re-lock!
	plugin.settings.autoLockMinutes = 1;
	await plugin.triggerSweep();

	assert.equal(targetFile.content, initialPlaintext);
	assert.equal(isLocked(targetFile.content), false);
});

test("permanentlyDecryptFiles permanently decrypts a group of notes and untracks already-unlocked ones", async () => {
	const password = "groupPassword123";
	const note1Plain = "Note 1 content";
	const note2Plain = "Note 2 content";
	const note3Plain = "Note 3 already unlocked content";

	const payload1 = await encryptContent(note1Plain, password, "vault", 100000);
	const payload2 = await encryptContent(note2Plain, password, "vault", 100000);
	const payload3 = await encryptContent(note3Plain, password, "vault", 100000);

	const { app, files } = createMockApp({
		"folder/note1.md": buildLockedNote(payload1),
		"folder/note2.md": buildLockedNote(payload2),
		"folder/note3.md": buildLockedNote(payload3),
	});

	const plugin = new TestLockyPlugin(app);
	plugin.suppliedPassword = password;
	plugin.confirmResponse = true;

	// Unlock note3 first so it's in unlocked map
	await plugin.unlockNote(files.get("folder/note3.md"));
	assert.equal(plugin.getUnlockedMap().size, 1);

	// Permanently decrypt all notes in the group
	const groupFiles = [
		files.get("folder/note1.md"),
		files.get("folder/note2.md"),
		files.get("folder/note3.md"),
	];
	await plugin.permanentlyDecryptFiles(groupFiles, "selected group");

	// All 3 notes should be plaintext and not locked
	for (const f of groupFiles) {
		assert.equal(isLocked(f.content), false);
	}
	assert.equal(files.get("folder/note1.md").content, note1Plain);
	assert.equal(files.get("folder/note2.md").content, note2Plain);
	assert.equal(files.get("folder/note3.md").content, note3Plain);

	// None should be in unlocked map or ledger
	assert.equal(plugin.getUnlockedMap().size, 0);
	assert.equal(plugin.getLedger().length, 0);

	// Sweep does not re-lock
	await plugin.triggerSweep();
	for (const f of groupFiles) {
		assert.equal(isLocked(f.content), false);
	}
});

test("permanentlyDecryptFolder permanently decrypts entire vault", async () => {
	const password = "vaultPassword123";
	const p1 = await encryptContent("Vault note 1", password, "vault", 100000);
	const p2 = await encryptContent("Vault note 2", password, "vault", 100000);

	const { app, files } = createMockApp({
		"v1.md": buildLockedNote(p1),
		"v2.md": buildLockedNote(p2),
		"plain.md": "Already plain note",
	});

	const plugin = new TestLockyPlugin(app);
	plugin.suppliedPassword = password;
	plugin.confirmResponse = true;

	await plugin.permanentlyDecryptFolder(app.vault.getRoot());

	assert.equal(files.get("v1.md").content, "Vault note 1");
	assert.equal(files.get("v2.md").content, "Vault note 2");
	assert.equal(files.get("plain.md").content, "Already plain note");
	assert.equal(isLocked(files.get("v1.md").content), false);
	assert.equal(isLocked(files.get("v2.md").content), false);
	assert.equal(plugin.getUnlockedMap().size, 0);
});

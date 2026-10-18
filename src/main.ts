import {
	MarkdownView,
	Menu,
	Notice,
	Plugin,
	setIcon,
	TAbstractFile,
	TFile,
	TFolder,
} from "obsidian";
import {
	decryptContent,
	DecryptError,
	encryptContent,
	encryptContentVerified,
	type LockerPayload,
	type LockerScope,
	SelfCheckError,
} from "./crypto";
import { buildLockedNote, isLocked, parseLockedNote, readScope } from "./format";
import { ConfirmModal } from "./ConfirmModal";
import { PasswordModal, type PasswordPromptOptions } from "./PasswordModal";
import { DEFAULT_SETTINGS, type LockerSettings, LockySettingTab } from "./settings";

const SWEEP_INTERVAL_MS = 30 * 1000;

/** Tracks a note that is currently decrypted on disk so it can be re-locked. */
interface UnlockedNote {
	password: string;
	scope: LockerScope;
	iterations: number;
	lastTouched: number;
}

/** One crash-recovery ledger entry: a path that held plaintext, plus its scope. */
interface LedgerEntry {
	path: string;
	scope: LockerScope;
}

/** Shape persisted via saveData: settings plus a crash-recovery ledger. */
interface PersistedData {
	settings: LockerSettings;
	/** Notes that held plaintext on disk at last write — used to recover after a crash. */
	ledger: LedgerEntry[];
}

export default class LockyPlugin extends Plugin {
	settings: LockerSettings = { ...DEFAULT_SETTINGS };

	/** Vault password cached for the session, never persisted to disk. */
	private vaultPassword: string | null = null;
	private vaultPasswordSetAt = 0;

	/** path -> details needed to re-lock an unlocked note. */
	private unlocked = new Map<string, UnlockedNote>();

	/** Serializes mutating operations per file path (lock/unlock/relock/decrypt). */
	private inFlight = new Set<string>();

	/** True while a bulk folder/vault operation runs, so auto-lock backs off. */
	private bulkActive = false;

	private statusBarEl: HTMLElement | null = null;
	private ribbonEl: HTMLElement | null = null;
	private lastActiveFile: string | null = null;

	/** Ledger read at startup, and notes found still exposed (plaintext) after a crash. */
	private startupLedger: LedgerEntry[] = [];
	private exposed: { file: TFile; scope: LockerScope }[] = [];

	async onload(): Promise<void> {
		await this.loadSettings();

		this.addSettingTab(new LockySettingTab(this.app, this));

		this.ribbonEl = this.addRibbonIcon("lock", "Locky: toggle lock on current note", async () => {
			await this.toggleActiveNote();
		});

		// Render the encrypted payload block as a compact placeholder in reading view
		// instead of a wall of base64. Supports both 'locky' and legacy 'locker' blocks.
		const renderPlaceholder = (_source: string, el: HTMLElement) => {
			el.createDiv({
				cls: "locker-blob locky-blob",
				text: "🔒 Locked note — unlock with Locky to view its contents.",
			});
		};
		this.registerMarkdownCodeBlockProcessor("locky", renderPlaceholder);
		this.registerMarkdownCodeBlockProcessor("locker", renderPlaceholder);

		this.statusBarEl = this.addStatusBarItem();
		this.statusBarEl.addClass("locker-status");
		this.statusBarEl.addClass("locky-status");
		this.statusBarEl.addEventListener("click", () => {
			if (this.unlocked.size > 0) void this.lockAll();
		});
		this.updateStatusBar();

		this.registerCommands();
		this.registerEvents();

		// One fixed-cadence sweep; it reads current settings each tick, so settings
		// changes take effect without re-registering (avoids leaking intervals).
		this.registerInterval(window.setInterval(() => void this.sweep(), SWEEP_INTERVAL_MS));

		this.app.workspace.onLayoutReady(() => {
			this.lastActiveFile = this.app.workspace.getActiveFile()?.path ?? null;
			void this.recoverExposedNotes();
		});
	}

	onunload(): void {
		// Obsidian does NOT await an async onunload, so this is best-effort: kick off
		// a re-lock of anything still decrypted. The persisted ledger lets the next
		// session detect and re-secure anything this didn't finish in time.
		void this.lockAll(true);
		this.vaultPassword = null;
	}

	private registerCommands(): void {
		this.addCommand({
			id: "lock-note",
			name: "Lock note (vault password)",
			checkCallback: (checking) => this.commandOnFile(checking, (f) => this.lockNote(f, "vault")),
		});
		this.addCommand({
			id: "lock-note-separate-password",
			name: "Lock note with a separate password",
			checkCallback: (checking) => this.commandOnFile(checking, (f) => this.lockNote(f, "note")),
		});
		this.addCommand({
			id: "unlock-note",
			name: "Unlock note",
			checkCallback: (checking) => this.commandOnFile(checking, (f) => this.unlockNote(f)),
		});
		this.addCommand({
			id: "permanently-decrypt-note",
			name: "Permanently decrypt note (remove encryption)",
			checkCallback: (checking) => this.commandOnFile(checking, (f) => this.permanentlyDecryptNote(f)),
		});
		this.addCommand({
			id: "lock-all",
			name: "Lock all currently-unlocked notes",
			callback: () => this.lockAll(),
		});

		this.addCommand({
			id: "lock-vault",
			name: "Lock every note in the vault (vault password)",
			callback: () => this.lockFolder(this.app.vault.getRoot()),
		});

		this.addCommand({
			id: "unlock-vault",
			name: "Unlock every vault-password note in the vault",
			callback: () => this.unlockFolder(this.app.vault.getRoot()),
		});

		this.addCommand({
			id: "permanently-decrypt-vault",
			name: "Permanently decrypt every vault-password note in the vault",
			callback: () => this.permanentlyDecryptFolder(this.app.vault.getRoot()),
		});

		this.addCommand({
			id: "forget-vault-password",
			name: "Forget vault password (lock session)",
			callback: () => this.forgetVaultPassword(),
		});
		this.addCommand({
			id: "secure-exposed",
			name: "Secure notes left exposed (after a crash)",
			checkCallback: (checking) => {
				if (this.exposed.length === 0) return false;
				if (!checking) void this.secureExposed();
				return true;
			},
		});
	}

	private registerEvents(): void {
		this.registerEvent(
			this.app.workspace.on("file-menu", (menu: Menu, file) => {
				if (file instanceof TFile && file.extension === "md") {
					this.addFileMenuItems(menu, file);
				} else if (file instanceof TFolder) {
					this.addFolderMenuItems(menu, file);
				}
			})
		);

		this.registerEvent(
			this.app.workspace.on("files-menu", (menu: Menu, files: TAbstractFile[]) => {
				const mdFiles = this.collectMarkdownFiles(files);
				if (mdFiles.length === 0) return;
				this.addFilesMenuItems(menu, mdFiles);
			})
		);

		// Auto-lock the note being left. Listen to both events: file-open misses
		// switches to non-file views / closing the last tab, which leaf-change catches.
		this.registerEvent(this.app.workspace.on("file-open", () => this.handleActiveChange()));
		this.registerEvent(this.app.workspace.on("active-leaf-change", () => this.handleActiveChange()));

		// Keep the unlocked-map keys (which are file paths) in sync with the vault.
		this.registerEvent(
			this.app.vault.on("rename", (file: TAbstractFile, oldPath: string) => {
				const info = this.unlocked.get(oldPath);
				if (info) {
					this.unlocked.delete(oldPath);
					this.unlocked.set(file.path, info);
					void this.persist();
				}
				if (this.lastActiveFile === oldPath) this.lastActiveFile = file.path;
			})
		);
		this.registerEvent(
			this.app.vault.on("delete", (file: TAbstractFile) => {
				if (this.unlocked.delete(file.path)) {
					void this.persist();
					this.updateStatusBar();
				}
			})
		);

		// Best-effort re-lock on app quit (in addition to onunload).
		this.registerEvent(
			// 'quit' is a real workspace event but not in the public typings.
			(this.app.workspace as { on(name: string, cb: () => void): import("obsidian").EventRef }).on(
				"quit",
				() => void this.lockAll(true)
			)
		);

		// Re-lock when the app/webview goes to the background. This is the ONLY
		// reliable re-lock signal on mobile: onunload and the 'quit' event are not
		// delivered on an OS-initiated suspend, and setInterval (the sweep) is frozen
		// while backgrounded. visibilitychange/pagehide fire on backgrounding in the
		// Capacitor webview, so they bound the plaintext-on-disk window on mobile.
		this.registerDomEvent(window.document, "visibilitychange", () => {
			if (window.document.hidden) void this.lockAll(true);
		});
		this.registerDomEvent(window, "pagehide", () => void this.lockAll(true));
	}

	// ---- settings & persistence ----------------------------------------

	async loadSettings(): Promise<void> {
		const raw = (await this.loadData()) as Partial<PersistedData> | LockerSettings | null;
		if (raw && typeof raw === "object" && "settings" in raw && raw.settings) {
			this.settings = Object.assign({}, DEFAULT_SETTINGS, raw.settings);
			this.startupLedger = normalizeLedger((raw as PersistedData).ledger);
		} else {
			// Back-compat: older data stored the settings object flat.
			this.settings = Object.assign({}, DEFAULT_SETTINGS, (raw as LockerSettings) ?? {});
			this.startupLedger = [];
		}
	}

	async saveSettings(): Promise<void> {
		await this.persist();
	}

	private async persist(): Promise<void> {
		const data: PersistedData = {
			settings: this.settings,
			ledger: Array.from(this.unlocked, ([path, info]) => ({ path, scope: info.scope })),
		};
		await this.saveData(data);
	}

	// ---- command plumbing ----------------------------------------------

	private commandOnFile(checking: boolean, run: (file: TFile) => Promise<void>): boolean {
		const file = this.app.workspace.getActiveFile();
		if (!file || file.extension !== "md") return false;
		if (!checking) void run(file);
		return true;
	}

	private addFileMenuItems(menu: Menu, file: TFile): void {
		menu.addItem((item) =>
			item
				.setTitle("Locky: lock note")
				.setIcon("lock")
				.onClick(() => this.lockNote(file, "vault"))
		);
		menu.addItem((item) =>
			item
				.setTitle("Locky: unlock note")
				.setIcon("unlock")
				.onClick(() => this.unlockNote(file))
		);
		menu.addItem((item) =>
			item
				.setTitle("Locky: permanently decrypt note")
				.setIcon("unlock")
				.onClick(() => this.permanentlyDecryptNote(file))
		);
	}

	private addFolderMenuItems(menu: Menu, folder: TFolder): void {
		if (this.notesInFolder(folder).length === 0) return; // nothing to act on
		menu.addItem((item) =>
			item
				.setTitle("Locky: lock all notes in folder")
				.setIcon("lock")
				.onClick(() => this.lockFolder(folder))
		);
		menu.addItem((item) =>
			item
				.setTitle("Locky: unlock all notes in folder")
				.setIcon("unlock")
				.onClick(() => this.unlockFolder(folder))
		);
		menu.addItem((item) =>
			item
				.setTitle("Locky: permanently decrypt all notes in folder")
				.setIcon("unlock")
				.onClick(() => this.permanentlyDecryptFolder(folder))
		);
	}

	private addFilesMenuItems(menu: Menu, files: TFile[]): void {
		const desc = `${files.length} selected note(s)`;
		menu.addItem((item) =>
			item
				.setTitle("Locky: lock selected notes (vault password)")
				.setIcon("lock")
				.onClick(() => this.lockFiles(files, desc))
		);
		menu.addItem((item) =>
			item
				.setTitle("Locky: unlock selected notes")
				.setIcon("unlock")
				.onClick(() => this.unlockFiles(files, desc))
		);
		menu.addItem((item) =>
			item
				.setTitle("Locky: permanently decrypt selected notes")
				.setIcon("unlock")
				.onClick(() => this.permanentlyDecryptFiles(files, desc))
		);
	}

	private async toggleActiveNote(): Promise<void> {
		const file = this.app.workspace.getActiveFile();
		if (!file) {
			new Notice("Locky: open a note first.");
			return;
		}
		if (file.extension !== "md") {
			new Notice(`Locky only locks markdown (.md) notes; "${file.name}" is a .${file.extension} file.`);
			return;
		}
		const content = await this.readLiveContent(file);
		if (isLocked(content)) {
			await this.unlockNote(file);
		} else {
			await this.lockNote(file, "vault");
		}
	}

	// ---- reading / writing safely --------------------------------------

	/** Every MarkdownView currently editing `file` (a note can be open in many panes/windows). */
	private findEditorViews(file: TFile): MarkdownView[] {
		const views: MarkdownView[] = [];
		for (const leaf of this.app.workspace.getLeavesOfType("markdown")) {
			const view = leaf.view;
			if (view instanceof MarkdownView && view.file && view.file.path === file.path) {
				views.push(view);
			}
		}
		return views;
	}

	/**
	 * Read the note's TRUE current content: the live editor buffer when it's open
	 * (which may contain unsaved keystrokes not yet flushed to disk), otherwise
	 * the file on disk. Reading the buffer is what prevents locking from silently
	 * encrypting away the user's most recent, unsaved edits.
	 */
	private async readLiveContent(file: TFile): Promise<string> {
		const views = this.findEditorViews(file);
		if (views.length > 0) return views[0].editor.getValue();
		return this.app.vault.read(file);
	}

	/**
	 * Write `next` to `file`, but only if its content still equals `expected`
	 * (i.e. nothing changed during the slow crypto step). Returns false without
	 * writing if it changed, so the caller can abort instead of clobbering.
	 *
	 *  - Open in editor(s): abort if ANY open buffer diverged, then set EVERY open
	 *    buffer so no stale pane can later re-flush over what we wrote (a note open
	 *    in two panes would otherwise clobber the ciphertext).
	 *  - Not open: use the atomic vault.process() read-modify-write.
	 */
	private async writeContent(file: TFile, expected: string, next: string): Promise<boolean> {
		const views = this.findEditorViews(file);
		if (views.length > 0) {
			if (views.some((v) => v.editor.getValue() !== expected)) return false;
			for (const v of views) v.editor.setValue(next);
			await this.app.vault.modify(file, next);
			return true;
		}
		let aborted = false;
		await this.app.vault.process(file, (current) => {
			if (current !== expected) {
				aborted = true;
				return current; // no-op write
			}
			return next;
		});
		return !aborted;
	}

	/**
	 * Run `fn` while holding an exclusive in-flight lock on `path`. Returns false
	 * (without running `fn`) if that path is already in flight — callers doing
	 * bulk work use this to count genuinely-skipped notes. Also a backstop catch
	 * so the many `void`-dispatched call sites can't surface unhandled rejections.
	 */
	private async withFileLock(path: string, fn: () => Promise<void>): Promise<boolean> {
		if (this.inFlight.has(path)) return false;
		this.inFlight.add(path);
		try {
			await fn();
		} catch (e) {
			console.error("Locky: operation failed", e);
			new Notice("Locky: operation failed. See console for details.");
		} finally {
			this.inFlight.delete(path);
		}
		return true;
	}

	// ---- lock / unlock / permanent decrypt -----------------------------

	async lockNote(file: TFile, scope: LockerScope): Promise<void> {
		const ran = await this.withFileLock(file.path, async () => {
			if (isLocked(await this.readLiveContent(file))) {
				new Notice("Locky: that note is already locked.");
				return;
			}

			const password =
				scope === "note"
					? await this.promptPassword({
							title: "Lock note with a separate password",
							description: `"${file.basename}" will need this exact password to unlock. There is no recovery.`,
							confirm: true,
							cta: "Lock",
						})
					: await this.ensureVaultPassword(true);
			if (!password) return;

			// Re-read AFTER the prompt so we encrypt the freshest content.
			const content = await this.readLiveContent(file);
			try {
				const payload = await this.seal(content, password, scope, this.settings.iterations);
				const written = await this.writeContent(file, content, buildLockedNote(payload));
				if (!written) {
					new Notice(`Locky: "${file.basename}" changed while locking — left unlocked.`);
					return;
				}
				this.unlocked.delete(file.path);
				await this.persist();
				this.updateStatusBar();
				new Notice(`Locky: locked "${file.basename}".`);
			} catch (e) {
				if (e instanceof SelfCheckError) {
					console.error("Locky: encryption self-check failed", e);
					new Notice("Locky: encryption self-check failed — note left unlocked to avoid data loss.");
				} else {
					console.error("Locky: failed to lock note", e);
					new Notice("Locky: failed to lock note. See console for details.");
				}
			}
		});
		if (!ran) new Notice("Locky: that note is busy — try again in a moment.");
	}

	async unlockNote(file: TFile): Promise<void> {
		const ran = await this.withFileLock(file.path, async () => {
			const content = await this.readLiveContent(file);
			const payload = parseLockedNote(content);
			if (!payload || !isLocked(content)) {
				new Notice("Locky: that note isn't locked.");
				return;
			}

			const scope = payload.scope ?? readScope(content);
			const password =
				scope === "note"
					? await this.promptPassword({
							title: "Unlock note",
							description: `Enter the password for "${file.basename}".`,
							cta: "Unlock",
						})
					: await this.ensureVaultPassword(false);
			if (!password) return;

			try {
				const plaintext = await decryptContent(payload, password);
				const written = await this.writeContent(file, content, plaintext);
				if (!written) {
					new Notice(`Locky: "${file.basename}" changed while unlocking — try again.`);
					return;
				}
				this.unlocked.set(file.path, {
					password,
					scope,
					iterations: payload.iterations,
					lastTouched: this.now(),
				});
				if (scope === "vault") this.cacheVaultPassword(password);
				await this.persist();
				this.updateStatusBar();
				new Notice(`Locky: unlocked "${file.basename}".`);
			} catch (e) {
				if (e instanceof DecryptError) {
					new Notice("Locky: incorrect password.");
					if (scope === "vault") this.forgetVaultPassword(true);
				} else {
					console.error("Locky: failed to unlock note", e);
					new Notice("Locky: failed to unlock note. See console for details.");
				}
			}
		});
		if (!ran) new Notice("Locky: that note is busy — try again in a moment.");
	}

	/**
	 * Permanently decrypts a note, completely undoing the encryption action.
	 * If the note was locked, prompts for the password, decrypts, and writes plaintext back to disk.
	 * If the note was already unlocked in memory, removes it from the auto-lock registry and persists.
	 * The note is no longer tracked or auto-locked, remaining plain markdown at rest.
	 */
	async permanentlyDecryptNote(file: TFile): Promise<void> {
		const ran = await this.withFileLock(file.path, async () => {
			// Case 1: Note is already unlocked in this session (plaintext on disk, tracked in unlocked map)
			if (this.unlocked.has(file.path)) {
				const confirmed = await this.confirmBulk(
					"permanently decrypt",
					1,
					`"${file.basename}"`,
					`"${file.basename}" is currently unlocked. Permanently decrypting will undo encryption, remove it from auto-lock, and keep it as a normal plain markdown note on disk.`
				);
				if (!confirmed) return;

				this.unlocked.delete(file.path);
				this.exposed = this.exposed.filter((e) => e.file.path !== file.path);
				await this.persist();
				this.updateStatusBar();
				new Notice(`Locky: permanently decrypted "${file.basename}".`);
				return;
			}

			// Case 2: Note is locked on disk
			const content = await this.readLiveContent(file);
			const payload = parseLockedNote(content);
			if (!payload || !isLocked(content)) {
				new Notice(`Locky: "${file.basename}" is not locked.`);
				return;
			}

			const scope = payload.scope ?? readScope(content);
			const password =
				scope === "note"
					? await this.promptPassword({
							title: "Permanently decrypt note",
							description: `Enter the password for "${file.basename}" to permanently remove encryption and restore plaintext.`,
							cta: "Permanently Decrypt",
						})
					: await this.ensureVaultPassword(false);
			if (!password) return;

			try {
				const plaintext = await decryptContent(payload, password);
				const written = await this.writeContent(file, content, plaintext);
				if (!written) {
					new Notice(`Locky: "${file.basename}" changed while decrypting — try again.`);
					return;
				}
				this.unlocked.delete(file.path);
				this.exposed = this.exposed.filter((e) => e.file.path !== file.path);
				if (scope === "vault") this.cacheVaultPassword(password);
				await this.persist();
				this.updateStatusBar();
				new Notice(`Locky: permanently decrypted "${file.basename}".`);
			} catch (e) {
				if (e instanceof DecryptError) {
					new Notice("Locky: incorrect password.");
					if (scope === "vault") this.forgetVaultPassword(true);
				} else {
					console.error("Locky: failed to permanently decrypt note", e);
					new Notice("Locky: failed to permanently decrypt note. See console for details.");
				}
			}
		});
		if (!ran) new Notice("Locky: that note is busy — try again in a moment.");
	}

	/** Re-encrypt a note that was previously unlocked, using its stored password. */
	private async relock(path: string): Promise<void> {
		await this.withFileLock(path, async () => {
			const info = this.unlocked.get(path);
			if (!info) return;

			const file = this.app.vault.getAbstractFileByPath(path);
			if (!(file instanceof TFile)) {
				this.unlocked.delete(path);
				await this.persist();
				this.updateStatusBar();
				return;
			}

			const content = await this.readLiveContent(file);
			if (isLocked(content)) {
				this.unlocked.delete(path);
				await this.persist();
				this.updateStatusBar();
				return; // already locked (e.g. user locked it manually)
			}

			// For vault-scoped notes prefer the CURRENT cached vault password, so an
			// auto-lock always matches the user's live vault password rather than a
			// stale snapshot captured at unlock time.
			const password =
				info.scope === "vault" ? this.vaultPassword ?? info.password : info.password;

			try {
				const payload = await this.seal(content, password, info.scope, info.iterations);
				const written = await this.writeContent(file, content, buildLockedNote(payload));
				if (!written) {
					new Notice(`Locky: "${file.basename}" changed while locking — left unlocked, will retry.`);
					return;
				}
				this.unlocked.delete(path);
				await this.persist();
			} catch (e) {
				console.error("Locky: failed to auto-lock note", e);
				new Notice(`Locky: could not auto-lock "${file.basename}" — it remains unlocked. See console.`);
			} finally {
				this.updateStatusBar();
			}
		});
	}

	async lockAll(silent = false): Promise<void> {
		// A bulk run manages its own locking; a user-triggered lock-all (status-bar
		// click / command, silent=false) must not interfere with it. The quit/
		// background re-lock paths pass silent=true and are allowed to force through.
		if (this.bulkActive && !silent) {
			new Notice("Locky: a bulk operation is in progress.");
			return;
		}
		const paths = Array.from(this.unlocked.keys());
		for (const path of paths) {
			await this.relock(path);
		}
		if (!silent) {
			new Notice(
				paths.length ? `Locky: locked ${paths.length} note(s).` : "Locky: nothing to lock."
			);
		}
	}

	// ---- bulk operations (folder, selected files, vault) ----------------

	/** All markdown notes at or under `folder` (recursive). */
	private notesInFolder(folder: TFolder): TFile[] {
		// A non-root folder path has no trailing slash; appending "/" ensures
		// "a" matches "a/x.md" but NOT a sibling "ab/x.md".
		const prefix = folder.isRoot() ? "" : folder.path + "/";
		return this.app.vault.getMarkdownFiles().filter((f) => f.path.startsWith(prefix));
	}

	/** Collect all unique markdown files from a list of files and folders. */
	private collectMarkdownFiles(items: TAbstractFile[]): TFile[] {
		const files: TFile[] = [];
		for (const item of items) {
			if (item instanceof TFile && item.extension === "md") {
				files.push(item);
			} else if (item instanceof TFolder) {
				files.push(...this.notesInFolder(item));
			}
		}
		const seen = new Set<string>();
		return files.filter((f) => {
			if (seen.has(f.path)) return false;
			seen.add(f.path);
			return true;
		});
	}

	/** Confirmation gate for mass operations. Overridable for tests. */
	protected confirmBulk(verb: string, count: number, where: string, customMessage?: string): Promise<boolean> {
		return new ConfirmModal(this.app, {
			title: `Locky: ${verb} ${count} note${count === 1 ? "" : "s"}?`,
			message:
				customMessage ??
				`This will ${verb} ${count} note${count === 1 ? "" : "s"} in ${where}.${
					verb.includes("decrypt")
						? " Plain markdown will be restored to disk and auto-lock will no longer re-encrypt."
						: ""
				}`,
			cta: verb.includes("decrypt") ? "Permanently Decrypt" : "Proceed",
		}).open();
	}

	private describeFolder(folder: TFolder): string {
		return folder.isRoot() ? "the entire vault" : `"${folder.path}"`;
	}

	/** Lock every currently-unlocked note in a list of files with the vault password. */
	async lockFiles(files: TFile[], targetDescription: string): Promise<void> {
		const work: { file: TFile; content: string }[] = [];
		for (const file of files) {
			try {
				const content = await this.readLiveContent(file);
				if (!isLocked(content)) work.push({ file, content });
			} catch (e) {
				console.error("Locky: could not read note for bulk lock", file.path, e);
			}
		}
		if (work.length === 0) {
			new Notice("Locky: no unlocked notes to lock here.");
			return;
		}
		if (!(await this.confirmBulk("encrypt", work.length, targetDescription))) return;

		const password = await this.ensureVaultPassword(true);
		if (!password) {
			new Notice("Locky: cancelled — no notes were changed.");
			return;
		}

		const progress = new Notice(`Locky: locking ${work.length} note(s)…`, 0);
		let locked = 0;
		let changed = 0;
		let failed = 0;
		let skipped = 0;
		const trouble: string[] = [];
		this.bulkActive = true;
		try {
			for (const { file, content } of work) {
				const ran = await this.withFileLock(file.path, async () => {
					try {
						const payload = await this.seal(content, password, "vault", this.settings.iterations);
						if (await this.writeContent(file, content, buildLockedNote(payload))) {
							this.unlocked.delete(file.path);
							locked++;
						} else {
							changed++;
							trouble.push(file.basename);
						}
					} catch (e) {
						console.error("Locky: failed to lock note in bulk", file.path, e);
						failed++;
						trouble.push(file.basename);
					}
				});
				if (!ran) skipped++;
			}
		} finally {
			this.bulkActive = false;
			try {
				await this.persist();
				this.updateStatusBar();
			} finally {
				progress.hide();
			}
		}
		new Notice(this.bulkSummary("locked", locked, { changed, failed, skipped }, trouble));
	}

	/** Lock every currently-unlocked note in a folder with the vault password. */
	lockFolder(folder: TFolder): Promise<void> {
		return this.lockFiles(this.notesInFolder(folder), this.describeFolder(folder));
	}

	/**
	 * Unlock every vault-password note in a list of files. Notes that use their own
	 * separate password are reported and skipped (unlock those individually).
	 */
	async unlockFiles(files: TFile[], targetDescription: string): Promise<void> {
		const work: { file: TFile; content: string; payload: LockerPayload }[] = [];
		let perNote = 0;
		for (const file of files) {
			try {
				const content = await this.readLiveContent(file);
				const payload = parseLockedNote(content);
				if (!payload || !isLocked(content)) continue;
				if ((payload.scope ?? readScope(content)) === "note") perNote++;
				else work.push({ file, content, payload });
			} catch (e) {
				console.error("Locky: could not read note for bulk unlock", file.path, e);
			}
		}
		if (work.length === 0) {
			new Notice(
				perNote > 0
					? `Locky: ${perNote} note(s) here use a separate password — unlock them individually.`
					: "Locky: no vault-password notes to unlock here."
			);
			return;
		}
		if (
			!(await this.confirmBulk(
				"decrypt (write plaintext for)",
				work.length,
				targetDescription
			))
		) {
			return;
		}

		const passwordWasCached = this.vaultPassword !== null;
		const password = await this.ensureVaultPassword(false);
		if (!password) {
			new Notice("Locky: cancelled — no notes were changed.");
			return;
		}

		const progress = new Notice(`Locky: unlocking ${work.length} note(s)…`, 0);
		let unlockedCount = 0;
		let wrongPassword = 0;
		let changed = 0;
		let failed = 0;
		let skipped = 0;
		const trouble: string[] = [];
		this.bulkActive = true;
		try {
			for (const { file, content, payload } of work) {
				const ran = await this.withFileLock(file.path, async () => {
					try {
						const plaintext = await decryptContent(payload, password);
						if (await this.writeContent(file, content, plaintext)) {
							this.unlocked.set(file.path, {
								password,
								scope: "vault",
								iterations: payload.iterations,
								lastTouched: this.now(),
							});
							await this.persist();
							unlockedCount++;
						} else {
							changed++;
							trouble.push(file.basename);
						}
					} catch (e) {
						if (e instanceof DecryptError) {
							wrongPassword++;
						} else {
							console.error("Locky: failed to unlock note in bulk", file.path, e);
							failed++;
						}
						trouble.push(file.basename);
					}
				});
				if (!ran) skipped++;
			}

			if (unlockedCount > 0) {
				this.cacheVaultPassword(password);
			} else if (!passwordWasCached && wrongPassword > 0 && changed === 0 && failed === 0) {
				this.forgetVaultPassword(true);
			}
		} finally {
			this.bulkActive = false;
			try {
				await this.persist();
				this.updateStatusBar();
			} finally {
				progress.hide();
			}
		}
		const extra = perNote ? ` ${perNote} use a separate password.` : "";
		new Notice(
			this.bulkSummary("unlocked", unlockedCount, { wrongPassword, changed, failed, skipped }, trouble) +
				extra
		);
	}

	/** Unlock every vault-password note in a folder. */
	unlockFolder(folder: TFolder): Promise<void> {
		return this.unlockFiles(this.notesInFolder(folder), this.describeFolder(folder));
	}

	/**
	 * Permanently decrypts a group of notes, completely undoing initial encryption.
	 * Decrypts locked vault-password notes, untracks any currently-unlocked notes,
	 * writes plain markdown, and prevents subsequent auto-locking.
	 * Notes that use their own separate password are reported.
	 */
	async permanentlyDecryptFiles(files: TFile[], targetDescription: string): Promise<void> {
		const work: { file: TFile; content: string; payload: LockerPayload }[] = [];
		const alreadyUnlocked: TFile[] = [];
		let perNote = 0;

		for (const file of files) {
			if (this.unlocked.has(file.path)) {
				alreadyUnlocked.push(file);
				continue;
			}
			try {
				const content = await this.readLiveContent(file);
				const payload = parseLockedNote(content);
				if (!payload || !isLocked(content)) continue;
				if ((payload.scope ?? readScope(content)) === "note") perNote++;
				else work.push({ file, content, payload });
			} catch (e) {
				console.error("Locky: could not read note for permanent decryption", file.path, e);
			}
		}

		const totalEligible = work.length + alreadyUnlocked.length;
		if (totalEligible === 0) {
			new Notice(
				perNote > 0
					? `Locky: ${perNote} note(s) here use a separate password — permanently decrypt them individually.`
					: "Locky: no encrypted notes found to decrypt here."
			);
			return;
		}

		if (
			!(await this.confirmBulk(
				"permanently decrypt",
				totalEligible,
				targetDescription
			))
		) {
			return;
		}

		let password = "";
		let passwordWasCached = false;
		if (work.length > 0) {
			passwordWasCached = this.vaultPassword !== null;
			const vaultPw = await this.ensureVaultPassword(false);
			if (!vaultPw) {
				new Notice("Locky: cancelled — no notes were changed.");
				return;
			}
			password = vaultPw;
		}

		const progress = new Notice(`Locky: permanently decrypting ${totalEligible} note(s)…`, 0);
		let decryptedCount = 0;
		let wrongPassword = 0;
		let changed = 0;
		let failed = 0;
		let skipped = 0;
		const trouble: string[] = [];
		this.bulkActive = true;

		try {
			// 1. Untrack and finalize notes that were already unlocked (plaintext on disk)
			for (const file of alreadyUnlocked) {
				const ran = await this.withFileLock(file.path, async () => {
					this.unlocked.delete(file.path);
					this.exposed = this.exposed.filter((e) => e.file.path !== file.path);
					decryptedCount++;
				});
				if (!ran) skipped++;
			}

			// 2. Decrypt and write plaintext for notes that were locked on disk
			for (const { file, content, payload } of work) {
				const ran = await this.withFileLock(file.path, async () => {
					try {
						const plaintext = await decryptContent(payload, password);
						if (await this.writeContent(file, content, plaintext)) {
							this.unlocked.delete(file.path);
							this.exposed = this.exposed.filter((e) => e.file.path !== file.path);
							decryptedCount++;
						} else {
							changed++;
							trouble.push(file.basename);
						}
					} catch (e) {
						if (e instanceof DecryptError) {
							wrongPassword++;
						} else {
							console.error("Locky: failed to permanently decrypt note in bulk", file.path, e);
							failed++;
						}
						trouble.push(file.basename);
					}
				});
				if (!ran) skipped++;
			}

			if (decryptedCount > 0 && work.length > 0) {
				this.cacheVaultPassword(password);
			} else if (!passwordWasCached && wrongPassword > 0 && changed === 0 && failed === 0) {
				this.forgetVaultPassword(true);
			}
		} finally {
			this.bulkActive = false;
			try {
				await this.persist();
				this.updateStatusBar();
			} finally {
				progress.hide();
			}
		}

		const extra = perNote ? ` ${perNote} use a separate password.` : "";
		new Notice(
			this.bulkSummary(
				"permanently decrypted",
				decryptedCount,
				{ wrongPassword, changed, failed, skipped },
				trouble
			) + extra
		);
	}

	/** Permanently decrypts all notes in a folder (or vault). */
	permanentlyDecryptFolder(folder: TFolder): Promise<void> {
		return this.permanentlyDecryptFiles(this.notesInFolder(folder), this.describeFolder(folder));
	}

	/** Build a human summary line for a bulk run, naming the notes that didn't complete. */
	private bulkSummary(
		verb: string,
		ok: number,
		issues: { wrongPassword?: number; changed?: number; failed?: number; skipped?: number },
		trouble: string[]
	): string {
		const parts: string[] = [];
		if (issues.wrongPassword) parts.push(`${issues.wrongPassword} wrong password`);
		if (issues.changed) parts.push(`${issues.changed} changed (retry)`);
		if (issues.failed) parts.push(`${issues.failed} failed`);
		if (issues.skipped) parts.push(`${issues.skipped} busy`);
		const names = trouble.length ? ` Left unchanged: ${trouble.slice(0, 5).join(", ")}${trouble.length > 5 ? "…" : ""}.` : "";
		return `Locky: ${verb} ${ok} note(s)${parts.length ? ` — ${parts.join(", ")}` : ""}.${names}`;
	}

	/**
	 * Encrypt content into a payload. When the verify setting is on, the result
	 * is round-trip checked so callers can safely overwrite the plaintext.
	 */
	private seal(
		plaintext: string,
		password: string,
		scope: LockerScope,
		iterations: number
	): Promise<LockerPayload> {
		if (this.settings.verifyOnLock) {
			return encryptContentVerified(plaintext, password, scope, iterations);
		}
		return encryptContent(plaintext, password, scope, iterations);
	}

	private updateStatusBar(): void {
		const count = this.unlocked.size;

		// Mirror the unlocked state onto the ribbon icon too, so there's a visible
		// indicator on mobile (where the status bar isn't shown).
		if (this.ribbonEl) {
			this.ribbonEl.toggleClass("locker-ribbon-warn", count > 0);
			this.ribbonEl.toggleClass("locky-ribbon-warn", count > 0);
			this.ribbonEl.setAttribute(
				"aria-label",
				count > 0
					? `Locky: ${count} note(s) unlocked — tap to lock the current note`
					: "Locky: toggle lock on current note"
			);
		}

		if (!this.statusBarEl) return;
		this.statusBarEl.empty();
		const icon = this.statusBarEl.createSpan({ cls: "locker-status-icon locky-status-icon" });
		setIcon(icon, count > 0 ? "unlock" : "lock");
		this.statusBarEl.createSpan({
			cls: "locker-status-text locky-status-text",
			text: count > 0 ? `${count} unlocked` : "Locked",
		});
		this.statusBarEl.toggleClass("locker-status-warn", count > 0);
		this.statusBarEl.toggleClass("locky-status-warn", count > 0);
		this.statusBarEl.setAttribute(
			"aria-label",
			count > 0
				? `Locky: ${count} note(s) unlocked (plaintext on disk) — click to lock all`
				: "Locky: no notes are unlocked"
		);
	}

	// ---- crash recovery -------------------------------------------------

	/** After load, find notes the ledger says were unlocked but are still plaintext. */
	private async recoverExposedNotes(): Promise<void> {
		const exposed: { file: TFile; scope: LockerScope }[] = [];
		for (const entry of this.startupLedger) {
			const file = this.app.vault.getAbstractFileByPath(entry.path);
			if (file instanceof TFile && file.extension === "md") {
				try {
					if (!isLocked(await this.app.vault.read(file))) exposed.push({ file, scope: entry.scope });
				} catch {
					/* unreadable; skip */
				}
			}
		}
		this.exposed = exposed;
		// Clear the stale on-disk ledger now that we've captured it (unlocked is empty
		// at startup, so this writes an empty ledger).
		await this.persist();
		if (exposed.length > 0) {
			new Notice(
				`Locky: ${exposed.length} note(s) may have been left unlocked after an unclean shutdown. ` +
					`Run "Locky: secure notes left exposed" to re-encrypt them.`,
				12000
			);
		}
	}

	/** Re-encrypt one exposed note at its ORIGINAL scope. Returns true if it ends up locked. */
	private async lockExposed(
		entry: { file: TFile; scope: LockerScope },
		password: string
	): Promise<boolean> {
		let ok = false;
		await this.withFileLock(entry.file.path, async () => {
			const content = await this.readLiveContent(entry.file);
			if (isLocked(content)) {
				ok = true; // someone already re-locked it
				return;
			}
			try {
				const payload = await this.seal(content, password, entry.scope, this.settings.iterations);
				ok = await this.writeContent(entry.file, content, buildLockedNote(payload));
			} catch (e) {
				console.error("Locky: failed to secure exposed note", entry.file.path, e);
			}
		});
		return ok;
	}

	private async secureExposed(): Promise<void> {
		// Vault-scoped notes re-lock with the vault password. Separate-password notes
		// CANNOT be faithfully recovered (their password was only in memory), so we
		// prompt for a new password per note rather than silently re-keying them to
		// the vault password.
		const vaultNotes = this.exposed.filter((e) => e.scope === "vault");
		const noteNotes = this.exposed.filter((e) => e.scope === "note");
		const stillExposed: { file: TFile; scope: LockerScope }[] = [];
		let secured = 0;

		if (vaultNotes.length > 0) {
			const password = await this.ensureVaultPassword(true);
			if (!password) {
				new Notice("Locky: cancelled — no notes were changed.");
				return;
			}
			for (const entry of vaultNotes) {
				if (await this.lockExposed(entry, password)) secured++;
				else stillExposed.push(entry);
			}
		}

		for (const entry of noteNotes) {
			const password = await this.promptPassword({
				title: `Re-secure "${entry.file.basename}"`,
				description: `This note used its own password, which can't be recovered after a crash. Set a NEW password to re-encrypt it (or cancel to leave it for now).`,
				confirm: true,
				cta: "Lock",
			});
			if (!password) {
				stillExposed.push(entry);
				continue;
			}
			if (await this.lockExposed(entry, password)) secured++;
			else stillExposed.push(entry);
		}

		this.exposed = stillExposed;
		new Notice(
			`Locky: secured ${secured} note(s).` +
				(stillExposed.length ? ` ${stillExposed.length} still exposed.` : "")
		);
	}

	// ---- vault password session ----------------------------------------

	/** Indirection point so tests can supply passwords without UI. */
	protected promptPassword(opts: PasswordPromptOptions): Promise<string | null> {
		return new PasswordModal(this.app, opts).open();
	}

	private async ensureVaultPassword(confirm: boolean): Promise<string | null> {
		if (this.vaultPassword) {
			this.vaultPasswordSetAt = this.now();
			return this.vaultPassword;
		}
		const password = await this.promptPassword({
			title: confirm ? "Set vault password" : "Enter vault password",
			description: confirm
				? "This password unlocks every note locked with the vault default. It is kept in memory only for this session and never written to disk."
				: "Enter your vault password to unlock this note.",
			confirm,
			cta: confirm ? "Lock" : "Unlock",
		});
		if (password) this.cacheVaultPassword(password);
		return password;
	}

	private cacheVaultPassword(password: string): void {
		this.vaultPassword = password;
		this.vaultPasswordSetAt = this.now();
	}

	forgetVaultPassword(silent = false): void {
		this.vaultPassword = null;
		this.vaultPasswordSetAt = 0;
		if (!silent) new Notice("Locky: forgot the cached vault password.");
	}

	// ---- events & timers ------------------------------------------------

	private handleActiveChange(): void {
		const current = this.app.workspace.getActiveFile()?.path ?? null;
		const previous = this.lastActiveFile;
		this.lastActiveFile = current;
		if (!this.settings.autoLockOnClose || this.bulkActive) return;
		if (previous && previous !== current && this.unlocked.has(previous)) {
			// Don't re-lock a note that's still open in another pane/window — the
			// inactivity sweep will catch it once it's genuinely idle.
			const prevFile = this.app.vault.getAbstractFileByPath(previous);
			if (prevFile instanceof TFile && this.findEditorViews(prevFile).length > 0) return;
			void this.relock(previous);
		}
	}

	private async sweep(): Promise<void> {
		// Don't fight a bulk run — it manages its own locking and password lifetime.
		if (this.bulkActive) return;
		const now = this.now();

		if (this.settings.autoLockMinutes > 0) {
			const maxAge = this.settings.autoLockMinutes * 60 * 1000;
			const active = this.app.workspace.getActiveFile()?.path ?? null;
			// Snapshot keys: relock() mutates the map mid-iteration.
			for (const path of Array.from(this.unlocked.keys())) {
				const info = this.unlocked.get(path);
				if (!info) continue;
				if (path === active) {
					info.lastTouched = now; // keep refreshing the note in view
					continue;
				}
				if (now - info.lastTouched >= maxAge) {
					await this.relock(path);
				}
			}
		}

		if (
			this.settings.forgetPasswordMinutes > 0 &&
			this.vaultPassword &&
			now - this.vaultPasswordSetAt >= this.settings.forgetPasswordMinutes * 60 * 1000
		) {
			this.forgetVaultPassword(true);
		}
	}

	private now(): number {
		return Date.now();
	}
}

export { LockyPlugin as LockerPlugin };

/** Parse a persisted ledger, tolerating the legacy string-array format (scope unknown -> vault). */
function normalizeLedger(raw: unknown): LedgerEntry[] {
	if (!Array.isArray(raw)) return [];
	const out: LedgerEntry[] = [];
	for (const e of raw) {
		if (typeof e === "string") {
			out.push({ path: e, scope: "vault" });
		} else if (e && typeof e === "object" && typeof (e as LedgerEntry).path === "string") {
			const scope: LockerScope = (e as LedgerEntry).scope === "note" ? "note" : "vault";
			out.push({ path: (e as LedgerEntry).path, scope });
		}
	}
	return out;
}

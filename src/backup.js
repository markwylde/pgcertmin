const { execSync, spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { EventEmitter } = require("node:events");

// Backup job state management
const backupState = {
	status: "idle", // idle, running, success, error
	type: null, // full, diff, incr
	startedAt: null,
	completedAt: null,
	error: null,
	output: null,
};

// Event emitter for SSE notifications
const backupEvents = new EventEmitter();
backupEvents.setMaxListeners(100); // Allow many concurrent SSE connections

function getBackupState() {
	return { ...backupState };
}

function setBackupState(updates) {
	Object.assign(backupState, updates);
	backupEvents.emit("stateChange", getBackupState());
}

function isBackupRunning() {
	return backupState.status === "running";
}

// Configuration from environment variables
const config = {
	stanza: process.env.PGBACKREST_STANZA || "main",
	configPath:
		process.env.PGBACKREST_CONFIG || "/etc/pgbackrest/pgbackrest.conf",
	logPath: process.env.PGBACKREST_LOG_PATH || "/var/log/pgbackrest",
	pgLogPath: process.env.PG_LOG_PATH || "/var/log/postgresql",
	s3: {
		bucket: process.env.PG_SEC_S3_BUCKET,
		endpoint: process.env.PG_SEC_S3_ENDPOINT || "s3.amazonaws.com",
		region: process.env.PG_SEC_S3_REGION || "us-east-1",
		accessKey: process.env.PG_SEC_S3_ACCESS_KEY,
		secretKey: process.env.PG_SEC_S3_SECRET_KEY,
	},
	pg: {
		// Only set host if data is truly remote (not mounted locally)
		// Set PGBACKREST_PG_HOST explicitly if you need SSH-based remote backup
		host: process.env.PGBACKREST_PG_HOST || null,
		port: process.env.PGPORT || "5432",
		user: process.env.PGBACKREST_PG_USER || process.env.PGUSER || "postgres",
		dataPath: process.env.PGBACKREST_PG_PATH || "/var/lib/postgresql/data",
		// SSL certificate paths for pgBackRest (may differ from app's paths)
		sslCa: process.env.PGBACKREST_SSL_CA || process.env.PGSSLROOTCERT,
		sslCert: process.env.PGBACKREST_SSL_CERT || process.env.PGSSLCERT,
		sslKey: process.env.PGBACKREST_SSL_KEY || process.env.PGSSLKEY,
	},
};

/**
 * Check if pgBackRest is installed and configured
 */
function checkPgBackRest() {
	try {
		execSync("pgbackrest version", { encoding: "utf8", stdio: "pipe" });
		return { installed: true, error: null };
	} catch (_err) {
		return {
			installed: false,
			error: "pgBackRest is not installed or not in PATH",
		};
	}
}

/**
 * Check if PostgreSQL is running by attempting a connection
 */
function checkPostgresRunning() {
	const { Client } = require("pg");
	return new Promise((resolve) => {
		const client = new Client({
			host: process.env.PGHOST || "localhost",
			port: process.env.PGPORT || 5432,
			database: process.env.PGDATABASE || "postgres",
			user: process.env.PGUSER || "postgres",
			password: process.env.PGPASSWORD,
			// SSL settings
			ssl: process.env.PGSSLMODE
				? {
						rejectUnauthorized:
							process.env.PGSSLMODE === "verify-ca" ||
							process.env.PGSSLMODE === "verify-full",
						ca: process.env.PGSSLROOTCERT
							? fs.readFileSync(process.env.PGSSLROOTCERT)
							: undefined,
						cert: process.env.PGSSLCERT
							? fs.readFileSync(process.env.PGSSLCERT)
							: undefined,
						key: process.env.PGSSLKEY
							? fs.readFileSync(process.env.PGSSLKEY)
							: undefined,
					}
				: false,
			connectionTimeoutMillis: 2000,
		});

		client
			.connect()
			.then(() => {
				client.end();
				resolve({ running: true });
			})
			.catch((err) => {
				resolve({ running: false, error: err.message });
			});
	});
}

/**
 * Check if the pgBackRest config file exists and has a valid stanza configuration
 */
function checkConfigFile() {
	try {
		const exists = fs.existsSync(config.configPath);
		if (!exists) {
			return { exists: false, valid: false, path: config.configPath };
		}

		// Read and validate the config file has the required stanza section
		const content = fs.readFileSync(config.configPath, "utf8");

		// Check for uncommented stanza section [stanza-name] and pg1-path
		const stanzaRegex = new RegExp(`^\\[${config.stanza}\\]\\s*$`, "m");
		const hasStanza = stanzaRegex.test(content);

		// Check for pg1-path in the config (not commented out)
		const pg1PathRegex = /^pg1-path\s*=/m;
		const hasPg1Path = pg1PathRegex.test(content);

		const valid = hasStanza && hasPg1Path;

		return {
			exists: true,
			valid,
			path: config.configPath,
			hasStanza,
			hasPg1Path,
			error: !valid
				? `Config missing ${!hasStanza ? `[${config.stanza}] stanza section` : ""}${!hasStanza && !hasPg1Path ? " and " : ""}${!hasPg1Path ? "pg1-path setting" : ""}`
				: null,
		};
	} catch (err) {
		return {
			exists: false,
			valid: false,
			path: config.configPath,
			error: err.message,
		};
	}
}

/**
 * Check if the stanza is configured (actually has backup.info in repo)
 */
function checkStanza() {
	try {
		const result = execSync(
			`pgbackrest --stanza=${config.stanza} --config=${config.configPath} info --output=json 2>&1`,
			{ encoding: "utf8", stdio: "pipe" },
		);
		const info = JSON.parse(result);
		// Check if stanza exists and has a valid status
		// Status code 0 = ok, 1 = missing stanza path, 2 = no valid backups but stanza exists
		// Status codes 1, 3, 4, 5 etc indicate stanza not properly configured
		if (info?.[0]?.status) {
			const statusCode = info[0].status.code;
			// Code 0 = ok, code 2 = ok but no backups yet
			if (statusCode === 0 || statusCode === 2) {
				return { configured: true, error: null, status: info[0].status };
			}
			return {
				configured: false,
				error: info[0].status.message,
				status: info[0].status,
			};
		}
		return { configured: false, error: "Unable to parse stanza info" };
	} catch (err) {
		return { configured: false, error: err.message };
	}
}

/**
 * Get backup information in JSON format
 */
function getBackupInfo() {
	try {
		const result = execSync(
			`pgbackrest --stanza=${config.stanza} --config=${config.configPath} info --output=json`,
			{ encoding: "utf8", stdio: "pipe", timeout: 30000 },
		);
		const info = JSON.parse(result);
		return { success: true, data: info };
	} catch (err) {
		return { success: false, error: err.message, data: null };
	}
}

/**
 * Parse backup info into a more usable format
 */
function parseBackupInfo(info) {
	if (!info || !info[0]) {
		return {
			stanza: config.stanza,
			status: "unknown",
			backups: [],
			database: null,
			archive: null,
		};
	}

	const stanzaInfo = info[0];
	const backups = (stanzaInfo.backup || []).map((b) => ({
		label: b.label,
		type: b.type, // full, diff, incr
		timestamp: {
			start: b.timestamp?.start ? new Date(b.timestamp.start * 1000) : null,
			stop: b.timestamp?.stop ? new Date(b.timestamp.stop * 1000) : null,
		},
		database: {
			id: b.database?.id,
			size: b.info?.size,
			sizeRepo: b.info?.repository?.size,
			sizeDelta: b.info?.repository?.delta,
		},
		reference: b.reference || [],
		prior: b.prior,
		lsn: {
			start: b.lsn?.start,
			stop: b.lsn?.stop,
		},
		error: b.error || false,
	}));

	return {
		stanza: stanzaInfo.name,
		status:
			stanzaInfo.status?.code === 0
				? "ok"
				: stanzaInfo.status?.message || "error",
		statusCode: stanzaInfo.status?.code,
		statusMessage: stanzaInfo.status?.message,
		cipher: stanzaInfo.cipher,
		backups: backups.reverse(), // Most recent first
		database: stanzaInfo.db || [],
		archive: stanzaInfo.archive || [],
		repo: stanzaInfo.repo || [],
	};
}

/**
 * Run a backup (full, differential, or incremental)
 * @param {string} type - 'full', 'diff', or 'incr'
 * @returns {object} - Returns immediately with status, backup runs in background
 */
async function runBackup(type = "incr") {
	const validTypes = ["full", "diff", "incr"];
	if (!validTypes.includes(type)) {
		return { success: false, error: `Invalid backup type: ${type}` };
	}

	// Check if backup is already running
	if (isBackupRunning()) {
		return { success: false, error: "A backup is already running" };
	}

	// Set state to running
	setBackupState({
		status: "running",
		type,
		startedAt: new Date().toISOString(),
		completedAt: null,
		error: null,
		output: null,
	});

	// Run backup in background (don't await)
	runBackupProcess(type);

	return { success: true, started: true, type };
}

/**
 * Internal function to run the backup process
 */
function runBackupProcess(type) {
	const args = [
		`--stanza=${config.stanza}`,
		`--config=${config.configPath}`,
		"backup",
		`--type=${type}`,
	];

	const proc = spawn("pgbackrest", args, {
		stdio: ["ignore", "pipe", "pipe"],
	});

	let stdout = "";
	let stderr = "";

	proc.stdout.on("data", (data) => {
		stdout += data.toString();
	});

	proc.stderr.on("data", (data) => {
		stderr += data.toString();
	});

	proc.on("close", (code) => {
		if (code === 0) {
			setBackupState({
				status: "success",
				completedAt: new Date().toISOString(),
				output: stdout,
				error: null,
			});
		} else {
			setBackupState({
				status: "error",
				completedAt: new Date().toISOString(),
				error: stderr || stdout || `Backup failed with code ${code}`,
				output: null,
			});
		}
	});

	proc.on("error", (err) => {
		setBackupState({
			status: "error",
			completedAt: new Date().toISOString(),
			error: err.message,
			output: null,
		});
	});
}

/**
 * Get recent log entries from pgBackRest
 */
function getRecentLogs(limit = 100) {
	try {
		const logDir = config.logPath;
		if (!fs.existsSync(logDir)) {
			return { success: false, error: "Log directory not found", logs: [] };
		}

		const files = fs
			.readdirSync(logDir)
			.filter((f) => f.endsWith(".log"))
			.sort()
			.reverse();

		if (files.length === 0) {
			return { success: true, logs: [], message: "No log files found" };
		}

		// Read the most recent log file
		const recentFile = path.join(logDir, files[0]);
		const content = fs.readFileSync(recentFile, "utf8");
		const lines = content
			.split("\n")
			.filter((l) => l.trim())
			.slice(-limit);

		// Parse log entries
		const logs = lines.map((line) => {
			// pgBackRest log format: TIMESTAMP P[ID] LEVEL: MESSAGE
			const match = line.match(
				/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+P(\d+)\s+(\w+):\s*(.*)$/,
			);
			if (match) {
				return {
					timestamp: match[1],
					pid: match[2],
					level: match[3],
					message: match[4],
				};
			}
			return { raw: line };
		});

		return { success: true, logs, file: files[0] };
	} catch (err) {
		return { success: false, error: err.message, logs: [] };
	}
}

/**
 * Get PostgreSQL logs, optionally filtered for archive-related entries
 * @param {object} options - Options for log retrieval
 * @param {number} options.limit - Maximum number of lines to return
 * @param {boolean} options.archiveOnly - Only return archive-related log entries
 */
function getPostgresLogs(options = {}) {
	const { limit = 100, archiveOnly = false } = options;

	try {
		const logDir = config.pgLogPath;
		if (!fs.existsSync(logDir)) {
			return {
				success: false,
				error: "PostgreSQL log directory not found",
				logs: [],
			};
		}

		// Look for the main log file (not CSV)
		const logFile = path.join(logDir, "postgresql");
		if (!fs.existsSync(logFile)) {
			// Try to find any log file
			const files = fs.readdirSync(logDir).filter((f) => !f.endsWith(".csv"));
			if (files.length === 0) {
				return {
					success: true,
					logs: [],
					message: "No PostgreSQL log files found",
				};
			}
		}

		const content = fs.readFileSync(logFile, "utf8");
		let lines = content.split("\n").filter((l) => l.trim());

		// Filter for archive-related entries if requested
		if (archiveOnly) {
			lines = lines.filter(
				(line) =>
					line.includes("archive") ||
					line.includes("pgbackrest") ||
					line.includes("WAL") ||
					line.includes("ERROR") ||
					line.includes("FATAL"),
			);
		}

		// Take the last N lines
		lines = lines.slice(-limit);

		// Parse log entries - pgBackRest logs in PostgreSQL log have format:
		// TIMESTAMP PID LEVEL: MESSAGE
		const logs = lines.map((line) => {
			// pgBackRest format: 2025-12-12 21:15:30.340 P00   INFO: message
			const pgbrMatch = line.match(
				/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+P(\d+)\s+(\w+):\s*(.*)$/,
			);
			if (pgbrMatch) {
				return {
					timestamp: pgbrMatch[1],
					pid: pgbrMatch[2],
					level: pgbrMatch[3],
					message: pgbrMatch[4],
					source: "pgbackrest",
				};
			}

			// PostgreSQL format: 2025-12-12 21:15:30.340 UTC [123] LOG: message
			const pgMatch = line.match(
				/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\w+\s+\[(\d+)\]\s+(\w+):\s*(.*)$/,
			);
			if (pgMatch) {
				return {
					timestamp: pgMatch[1],
					pid: pgMatch[2],
					level: pgMatch[3],
					message: pgMatch[4],
					source: "postgresql",
				};
			}

			// Continuation lines (indented with spaces, like HINT lines)
			if (line.match(/^\s+/)) {
				return {
					message: line.trim(),
					continuation: true,
				};
			}

			return { raw: line };
		});

		return { success: true, logs, file: "postgresql" };
	} catch (err) {
		return { success: false, error: err.message, logs: [] };
	}
}

/**
 * Get backup statistics summary
 */
function getBackupStats(parsedInfo) {
	if (!parsedInfo || !parsedInfo.backups || parsedInfo.backups.length === 0) {
		return {
			totalBackups: 0,
			fullBackups: 0,
			diffBackups: 0,
			incrBackups: 0,
			lastBackup: null,
			lastFullBackup: null,
			totalSize: 0,
			totalRepoSize: 0,
			oldestBackup: null,
		};
	}

	const backups = parsedInfo.backups;
	const fullBackups = backups.filter((b) => b.type === "full");
	const diffBackups = backups.filter((b) => b.type === "diff");
	const incrBackups = backups.filter((b) => b.type === "incr");

	const totalRepoSize = backups.reduce(
		(sum, b) => sum + (b.database.sizeRepo || 0),
		0,
	);
	const totalSize = backups.reduce((sum, b) => sum + (b.database.size || 0), 0);

	return {
		totalBackups: backups.length,
		fullBackups: fullBackups.length,
		diffBackups: diffBackups.length,
		incrBackups: incrBackups.length,
		lastBackup: backups[0] || null,
		lastFullBackup: fullBackups[0] || null,
		totalSize,
		totalRepoSize,
		oldestBackup: backups[backups.length - 1] || null,
		compressionRatio:
			totalSize > 0 ? ((1 - totalRepoSize / totalSize) * 100).toFixed(1) : 0,
	};
}

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes) {
	if (!bytes || bytes === 0) return "0 B";
	const k = 1024;
	const sizes = ["B", "KB", "MB", "GB", "TB"];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}

/**
 * Check S3 configuration
 */
function checkS3Config() {
	const missing = [];
	if (!config.s3.bucket) missing.push("PG_SEC_S3_BUCKET");
	if (!config.s3.accessKey) missing.push("PG_SEC_S3_ACCESS_KEY");
	if (!config.s3.secretKey) missing.push("PG_SEC_S3_SECRET_KEY");

	return {
		configured: missing.length === 0,
		missing,
		config: {
			bucket: config.s3.bucket || "(not set)",
			endpoint: config.s3.endpoint,
			region: config.s3.region,
		},
	};
}

/**
 * Generate pgBackRest configuration for S3
 */
function generateConfig() {
	const lines = [
		"[global]",
		"repo1-type=s3",
		`repo1-path=/backup/${config.stanza}`,
		`repo1-s3-bucket=${config.s3.bucket}`,
		`repo1-s3-endpoint=${config.s3.endpoint}`,
		`repo1-s3-region=${config.s3.region}`,
		`repo1-s3-key=${config.s3.accessKey}`,
		`repo1-s3-key-secret=${config.s3.secretKey}`,
		"repo1-retention-full=2",
		"repo1-retention-diff=7",
		"",
		"process-max=2",
		"log-level-console=info",
		"log-level-file=detail",
		"start-fast=y",
		"delta=y",
		"# Disable archive check since pgBackRest is in a separate container from PostgreSQL",
		"archive-check=n",
		"",
		`[${config.stanza}]`,
		`pg1-path=${config.pg.dataPath}`,
		`pg1-socket-path=/var/run/postgresql`,
	];

	// Add PostgreSQL host only if explicitly set (for SSH-based remote backup)
	// Don't set this if the data directory is mounted locally (Docker shared volume)
	if (config.pg.host) {
		lines.push(`pg1-host=${config.pg.host}`);

		// These settings only apply when using pg1-host (SSH connection)
		if (config.pg.sslCa) {
			lines.push(`pg1-host-ca-file=${config.pg.sslCa}`);
		}
		if (config.pg.sslCert) {
			lines.push(`pg1-host-cert-file=${config.pg.sslCert}`);
		}
		if (config.pg.sslKey) {
			lines.push(`pg1-host-key-file=${config.pg.sslKey}`);
		}
	}

	// Add port if not default (for local socket connections)
	if (config.pg.port && config.pg.port !== "5432") {
		lines.push(`pg1-port=${config.pg.port}`);
	}

	// Add user for PostgreSQL connections
	if (config.pg.user) {
		lines.push(`pg1-user=${config.pg.user}`);
	}

	return `${lines.join("\n")}\n`;
}

/**
 * Write the pgBackRest configuration file
 */
function writeConfig() {
	try {
		const configContent = generateConfig();
		const configDir = path.dirname(config.configPath);

		// Create directory if it doesn't exist
		if (!fs.existsSync(configDir)) {
			fs.mkdirSync(configDir, { recursive: true });
		}

		fs.writeFileSync(config.configPath, configContent, {
			encoding: "utf8",
			mode: 0o600,
		});
		return { success: true, path: config.configPath };
	} catch (err) {
		return { success: false, error: err.message };
	}
}

/**
 * Get the overall system status for backups
 */
async function getSystemStatus() {
	const pgbackrest = checkPgBackRest();
	const s3 = checkS3Config();
	const configFile = checkConfigFile();
	const stanzaCheck = pgbackrest.installed
		? checkStanza()
		: { configured: false, error: "pgBackRest not installed" };

	let backupInfo = null;
	let parsedInfo = null;
	let stats = null;

	if (pgbackrest.installed && stanzaCheck.configured) {
		backupInfo = getBackupInfo();
		if (backupInfo.success) {
			parsedInfo = parseBackupInfo(backupInfo.data);
			stats = getBackupStats(parsedInfo);
		}
	}

	return {
		pgbackrest,
		s3,
		configFile,
		stanza: stanzaCheck,
		backupInfo: parsedInfo,
		stats,
		config: {
			stanza: config.stanza,
			configPath: config.configPath,
			logPath: config.logPath,
			pgHost: config.pg.host,
			pgPort: config.pg.port,
			pgUser: config.pg.user,
			pgPath: config.pg.dataPath,
			pgSslCa: config.pg.sslCa,
			pgSslCert: config.pg.sslCert,
			pgSslKey: config.pg.sslKey,
		},
	};
}

/**
 * Create a new stanza (initialize the backup repository)
 * @param {object} options - Options for stanza creation
 * @param {boolean} options.noOnline - Skip online check (useful when PostgreSQL is on a remote host without SSH)
 */
async function createStanza(options = {}) {
	return new Promise((resolve) => {
		const args = [
			`--stanza=${config.stanza}`,
			`--config=${config.configPath}`,
			"stanza-create",
		];

		// Add --no-online if PostgreSQL is remote and we can't SSH to it
		if (options.noOnline) {
			args.push("--no-online");
		}

		const proc = spawn("pgbackrest", args, {
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";

		proc.stdout.on("data", (data) => {
			stdout += data.toString();
		});

		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("close", (code) => {
			if (code === 0) {
				resolve({ success: true, output: stdout });
			} else {
				resolve({ success: false, error: stderr || stdout, code });
			}
		});

		proc.on("error", (err) => {
			resolve({ success: false, error: err.message });
		});
	});
}

/**
 * Run a check on the stanza configuration
 */
async function runCheck() {
	return new Promise((resolve) => {
		const args = [
			`--stanza=${config.stanza}`,
			`--config=${config.configPath}`,
			"check",
		];

		const proc = spawn("pgbackrest", args, {
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";

		proc.stdout.on("data", (data) => {
			stdout += data.toString();
		});

		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("close", (code) => {
			if (code === 0) {
				resolve({ success: true, output: stdout });
			} else {
				resolve({ success: false, error: stderr || stdout, code });
			}
		});

		proc.on("error", (err) => {
			resolve({ success: false, error: err.message });
		});
	});
}

/**
 * Restore from a specific backup
 * @param {string} backupLabel - The backup label to restore from (e.g., "20231212-123456F")
 * @param {object} options - Optional restore options
 * @param {boolean} options.delta - Use delta restore (only restore changed files, default: true)
 * @returns {Promise<object>} - Result of the restore operation
 *
 * NOTE: This function expects PostgreSQL to already be stopped.
 * For containerized environments, the container should be stopped before calling this.
 */
async function restoreBackup(backupLabel, options = {}) {
	return new Promise((resolve) => {
		if (!backupLabel) {
			return resolve({ success: false, error: "Backup label is required" });
		}

		const args = [
			`--stanza=${config.stanza}`,
			`--config=${config.configPath}`,
			`--set=${backupLabel}`,
		];

		// Use delta restore by default (only restore changed files)
		if (options.delta !== false) {
			args.push("--delta");
		}

		args.push("restore");

		const proc = spawn("pgbackrest", args, {
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";

		proc.stdout.on("data", (data) => {
			stdout += data.toString();
		});

		proc.stderr.on("data", (data) => {
			stderr += data.toString();
		});

		proc.on("close", (code) => {
			if (code === 0) {
				resolve({ success: true, output: stdout, backupLabel });
			} else {
				resolve({ success: false, error: stderr || stdout, code, backupLabel });
			}
		});

		proc.on("error", (err) => {
			resolve({ success: false, error: err.message, backupLabel });
		});
	});
}

module.exports = {
	config,
	checkPgBackRest,
	checkPostgresRunning,
	checkStanza,
	getBackupInfo,
	parseBackupInfo,
	runBackup,
	restoreBackup,
	getRecentLogs,
	getPostgresLogs,
	getBackupStats,
	formatBytes,
	checkS3Config,
	generateConfig,
	writeConfig,
	getSystemStatus,
	createStanza,
	runCheck,
	// Backup state management
	getBackupState,
	isBackupRunning,
	backupEvents,
};

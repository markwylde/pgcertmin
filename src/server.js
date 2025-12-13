const express = require("express");
const { Eta } = require("eta");
const path = require("node:path");
const fs = require("node:fs");
const helmet = require("helmet");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const crypto = require("node:crypto");

const app = express();
const PORT = process.env.PORT || 8780;
const COOKIE_SECRET =
	process.env.COOKIE_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_COOKIE_NAME = "pgsecmin_session";

// Multer for file uploads (memory storage)
const upload = multer({
	storage: multer.memoryStorage(),
	limits: { fileSize: 10 * 1024 },
}); // 10KB max

// Middleware
app.use(
	helmet({
		contentSecurityPolicy: {
			directives: {
				...helmet.contentSecurityPolicy.getDefaultDirectives(),
				"script-src": ["'self'", "'unsafe-inline'"],
				"script-src-attr": ["'unsafe-inline'"],
				"upgrade-insecure-requests": null,
			},
		},
		hsts: false,
	}),
);
app.use(compression());
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(COOKIE_SECRET));

// IP Restriction Middleware
const ALLOWED_LOCALS = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];

app.use((req, res, next) => {
	let clientIp = req.ip || req.connection.remoteAddress;

	// Normalize IPv6 mapped IPv4 addresses
	if (clientIp.startsWith("::ffff:")) {
		clientIp = clientIp.substring(7);
	}

	if (
		ALLOWED_LOCALS.includes(clientIp) ||
		ALLOWED_LOCALS.includes(req.connection.remoteAddress)
	) {
		return next();
	}

	// Simple check for now - if it's not IPv4, we block it unless it's loopback
	// Tailscale is 100.x.y.z which is IPv4.
	if (clientIp.includes(":")) {
		console.warn(`Blocked non-IPv4 access: ${clientIp}`);
		return res.status(403).send("Forbidden");
	}

	next();
});

// Authentication helpers
const CLIENT_CERTS_DIR =
	process.env.CLIENT_CERTS_DIR || "/data/certs/postgres-clients/";

function createSessionToken(certName) {
	const payload = JSON.stringify({ cert: certName, ts: Date.now() });
	const hmac = crypto.createHmac("sha256", COOKIE_SECRET);
	hmac.update(payload);
	const signature = hmac.digest("hex");
	return Buffer.from(`${payload}.${signature}`).toString("base64");
}

function verifySessionToken(token) {
	try {
		const decoded = Buffer.from(token, "base64").toString("utf8");
		const lastDot = decoded.lastIndexOf(".");
		if (lastDot === -1) return null;

		const payload = decoded.substring(0, lastDot);
		const signature = decoded.substring(lastDot + 1);

		const hmac = crypto.createHmac("sha256", COOKIE_SECRET);
		hmac.update(payload);
		const expectedSig = hmac.digest("hex");

		if (signature !== expectedSig) return null;

		return JSON.parse(payload);
	} catch {
		return null;
	}
}

async function validateKeyFile(keyContent) {
	// Compare uploaded key with existing keys in the certs directory
	try {
		const files = await fs.promises.readdir(CLIENT_CERTS_DIR);
		const keyFiles = files.filter((f) => f.endsWith(".key") && f !== "ca.key");

		for (const keyFile of keyFiles) {
			const existingKey = await fs.promises.readFile(
				path.join(CLIENT_CERTS_DIR, keyFile),
				"utf8",
			);
			// Normalize line endings and trim for comparison
			if (existingKey.trim() === keyContent.trim()) {
				return keyFile.replace(".key", "");
			}
		}
		return null;
	} catch (e) {
		console.error("Error validating key:", e);
		return null;
	}
}

// Authentication middleware
function requireAuth(req, res, next) {
	const token = req.signedCookies[SESSION_COOKIE_NAME];
	if (!token) {
		return res.redirect("/login");
	}

	const session = verifySessionToken(token);
	if (!session || !session.cert) {
		res.clearCookie(SESSION_COOKIE_NAME);
		return res.redirect("/login");
	}

	// Attach session info to request
	req.session = session;
	res.locals.certName = session.cert;
	next();
}

// View Engine Setup
const viewDir = path.join(__dirname, "../views");
const eta = new Eta({ views: viewDir, autoTrim: false });

app.engine("eta", (filePath, options, callback) => {
	try {
		// Express passes the absolute path, but Eta with 'views' option expects a relative path or key.
		// We compute the relative path from the views directory.
		const relativePath = path.relative(viewDir, filePath);

		const html = eta.render(relativePath, options);
		callback(null, html);
	} catch (err) {
		console.error("Eta Render Error:", err);
		callback(err);
	}
});
app.set("view engine", "eta");
app.set("views", viewDir);

// Routes
const db = require("./db");

// Login routes (not protected by auth)
app.get("/login", (req, res) => {
	// If already logged in, redirect to dashboard
	const token = req.signedCookies[SESSION_COOKIE_NAME];
	if (token) {
		const session = verifySessionToken(token);
		if (session?.cert) {
			return res.redirect("/");
		}
	}
	res.render("login", { title: "Login", error: null });
});

app.post("/login", upload.single("keyfile"), async (req, res) => {
	try {
		if (!req.file) {
			return res.render("login", {
				title: "Login",
				error: "No key file uploaded",
			});
		}

		const keyContent = req.file.buffer.toString("utf8");
		const certName = await validateKeyFile(keyContent);

		if (!certName) {
			return res.render("login", {
				title: "Login",
				error: "Invalid key file. No matching certificate found.",
			});
		}

		// Create session token and set cookie
		const token = createSessionToken(certName);
		res.cookie(SESSION_COOKIE_NAME, token, {
			signed: true,
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
		});

		res.redirect("/");
	} catch (err) {
		console.error("Login error:", err);
		res.render("login", {
			title: "Login",
			error: "An error occurred during login",
		});
	}
});

app.post("/logout", (_req, res) => {
	res.clearCookie(SESSION_COOKIE_NAME);
	res.redirect("/login");
});

// Apply authentication middleware to all routes below
app.use(requireAuth);

// Make db connection info available to all views
app.use((_req, res, next) => {
	res.locals.dbUser = db.config.user;
	res.locals.dbHost = db.config.host;
	next();
});

app.get("/", async (_req, res) => {
	try {
		const dbCount = await db.query("SELECT count(*) FROM pg_database");
		const userCount = await db.query("SELECT count(*) FROM pg_roles");
		// Fetch Cert count
		const certs = await require("./certs").listCerts();

		// Fetch Live Activity
		const activity = await db.query(`
            SELECT 
                a.pid, 
                a.usename, 
                a.client_addr, 
                a.backend_start, 
                a.state,
                a.query,
                s.ssl, 
                s.version, 
                s.cipher, 
                s.client_dn
            FROM pg_stat_activity a
            LEFT JOIN pg_stat_ssl s ON a.pid = s.pid
            WHERE a.pid <> pg_backend_pid() 
            AND a.state IS NOT NULL
            ORDER BY a.backend_start DESC
            LIMIT 10;
        `);

		// Fetch Login History from logs
		let history = [];
		try {
			const historyResult = await db.query(`
                SELECT log_time, user_name, database_name, connection_from, message
                FROM postgres_log 
                WHERE (message like '%connection received%' OR message like '%connection authorized%')
                ORDER BY log_time DESC 
                LIMIT 10
            `);
			history = historyResult.rows;
		} catch (e) {
			console.warn(
				"Could not fetch log history (maybe table missing?):",
				e.message,
			);
		}

		res.render("index", {
			title: "Dashboard",
			path: "/",
			stats: {
				dbs: dbCount.rows[0].count,
				users: userCount.rows[0].count,
				certs: certs.length,
				status: "Online",
			},
			activity: activity.rows,
			history: history,
		});
	} catch (err) {
		console.error(err);
		res.render("index", {
			title: "Dashboard - Error connecting to DB",
			path: "/",
			stats: { dbs: "-", users: "-", certs: "-", status: "Error" },
			activity: [],
			history: [],
		});
	}
});

app.get("/databases", async (_req, res) => {
	try {
		const result = await db.query(`
            SELECT d.datname as name, 
                   pg_catalog.pg_get_userbyid(d.datdba) as owner,
                   pg_catalog.pg_encoding_to_char(d.encoding) as encoding,
                   d.datcollate as collate,
                   d.datctype as ctype,
                   pg_catalog.pg_size_pretty(pg_catalog.pg_database_size(d.datname)) as size
            FROM pg_catalog.pg_database d
            ORDER BY d.datname;
        `);

		const usersResult = await db.query(
			"SELECT rolname FROM pg_roles ORDER BY rolname",
		);

		res.render("databases", {
			title: "Databases",
			path: "/databases",
			databases: result.rows,
			users: usersResult.rows,
		});
	} catch (err) {
		console.error(err);
		res.render("databases", {
			title: "Databases - Error",
			path: "/databases",
			databases: [],
			users: [],
		});
	}
});

app.post("/databases/create", async (req, res) => {
	try {
		const { name, owner } = req.body;
		if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) {
			throw new Error(
				"Invalid database name. Use only letters, numbers, and underscores.",
			);
		}

		// Escape identifier
		const safeName = `"${name}"`;
		let query = `CREATE DATABASE ${safeName}`;

		if (owner && /^[a-zA-Z0-9_]+$/.test(owner)) {
			query += ` OWNER "${owner}"`;
		}

		await db.query(query);
		res.redirect("/databases");
	} catch (err) {
		console.error(err);
		// For now, simpler error handling: send text. ideally render with error message.
		res.status(500).send(`Error creating database: ${err.message}`);
	}
});

app.post("/databases/:name/delete", async (req, res) => {
	try {
		const { name } = req.params;
		if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) {
			throw new Error(
				"Invalid database name. Use only letters, numbers, and underscores.",
			);
		}

		// Prevent deletion of critical system databases
		const protectedDbs = ["postgres", "template0", "template1"];
		if (protectedDbs.includes(name.toLowerCase())) {
			throw new Error(`Cannot delete system database: ${name}`);
		}

		// Terminate all connections to the database first
		await db.query(`
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = '${name.replace(/'/g, "''")}'
			AND pid <> pg_backend_pid()
		`);

		// Drop the database
		const safeName = `"${name}"`;
		await db.query(`DROP DATABASE ${safeName}`);

		res.redirect("/databases");
	} catch (err) {
		console.error(err);
		res.status(500).send(`Error deleting database: ${err.message}`);
	}
});

app.get("/users", async (_req, res) => {
	try {
		const result = await db.query(`
            SELECT r.rolname as name, 
                   r.rolsuper as superuser, 
                   r.rolcreaterole as createrole,
                   r.rolcreatedb as createdb,
                   r.rolcanlogin as canlogin,
                   CASE WHEN r.rolvaliduntil IS NULL THEN 'Never' ELSE r.rolvaliduntil::text END as expiry
            FROM pg_catalog.pg_roles r
            ORDER BY r.rolname;
        `);

		const allUsers = result.rows;
		const systemUsers = allUsers.filter(
			(u) => u.name.trim().startsWith("pg_") || u.name.trim() === "postgres",
		);
		const regularUsers = allUsers.filter(
			(u) => !u.name.trim().startsWith("pg_") && u.name.trim() !== "postgres",
		);

		const dbsResult = await db.query(
			"SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname",
		);

		res.render("users", {
			title: "Users",
			path: "/users",
			users: regularUsers,
			systemUsers: systemUsers,
			databases: dbsResult.rows,
		});
	} catch (err) {
		console.error(err);
		res.render("users", {
			title: "Users - Error",
			path: "/users",
			users: [],
			systemUsers: [],
			databases: [],
		});
	}
});

app.post("/users/create", async (req, res) => {
	try {
		const {
			name,
			password,
			superuser,
			createrole,
			createdb,
			canlogin,
			create_new_db,
			new_db_name,
			access_dbs,
		} = req.body;

		if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) {
			throw new Error(
				"Invalid username. Use only letters, numbers, and underscores.",
			);
		}

		if (!password) {
			throw new Error("Password is required.");
		}

		const safeName = `"${name}"`;
		const options = [];
		if (superuser) options.push("SUPERUSER");
		if (createrole) options.push("CREATEROLE");
		if (createdb) options.push("CREATEDB");
		if (canlogin) options.push("LOGIN");
		else options.push("NOLOGIN");

		// Escape single quotes in password
		const safePassword = password.replace(/'/g, "''");

		// 1. Create User
		await db.query(
			`CREATE USER ${safeName} WITH PASSWORD '${safePassword}' ${options.join(" ")}`,
		);

		// 2. Create New Database (if requested)
		if (create_new_db && new_db_name) {
			if (!/^[a-zA-Z0-9_]+$/.test(new_db_name)) {
				console.warn("Skipping invalid new DB name:", new_db_name);
			} else {
				// Create DB with this user as owner
				await db.query(`CREATE DATABASE "${new_db_name}" OWNER ${safeName}`);
			}
		}

		// 3. Grant Access to Existing Databases
		// access_dbs can be a string (one) or array (multiple) or undefined
		if (access_dbs) {
			const dbs = Array.isArray(access_dbs) ? access_dbs : [access_dbs];
			for (const dbName of dbs) {
				if (/^[a-zA-Z0-9_]+$/.test(dbName)) {
					// Grant all privileges on the database to the user
					// Note: You cannot run GRANT inside a transaction block easily if using one,
					// but here we are auto-commit.
					try {
						// We are connecting to 'postgres' usually. Granting on another DB
						// requires connecting to that DB or just granting "CREATE" etc?
						// "GRANT ALL ON DATABASE x TO y" grants rights *on the database object* (create schema, connect, temp).
						// It does NOT grant access to tables inside it automatically unless we alter default privileges or grant schema usage.
						// But for "access", GRANT ALL ON DATABASE is the standard starting point.
						await db.query(`GRANT ALL ON DATABASE "${dbName}" TO ${safeName}`);
					} catch (e) {
						console.error(`Failed to grant access to ${dbName}:`, e.message);
					}
				}
			}
		}

		res.redirect("/users");
	} catch (err) {
		console.error(err);
		res.status(500).send(`Error creating user: ${err.message}`);
	}
});

app.post("/users/:name/delete", async (req, res) => {
	try {
		const { name } = req.params;
		if (!name || !/^[a-zA-Z0-9_]+$/.test(name)) {
			throw new Error(
				"Invalid username. Use only letters, numbers, and underscores.",
			);
		}

		// Prevent deletion of critical system users
		const protectedUsers = ["postgres"];
		if (
			protectedUsers.includes(name.toLowerCase()) ||
			name.toLowerCase().startsWith("pg_")
		) {
			throw new Error(`Cannot delete system user: ${name}`);
		}

		// Terminate all connections for this user first
		await db.query(`
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE usename = '${name.replace(/'/g, "''")}'
			AND pid <> pg_backend_pid()
		`);

		// Drop the user/role
		const safeName = `"${name}"`;
		await db.query(`DROP ROLE ${safeName}`);

		res.redirect("/users");
	} catch (err) {
		console.error(err);
		res.status(500).send(`Error deleting user: ${err.message}`);
	}
});

// Cert Routes
const certManager = require("./certs");

app.get("/certs", async (_req, res) => {
	try {
		const certs = await certManager.listCerts();
		const usersResult = await db.query(
			"SELECT rolname FROM pg_roles ORDER BY rolname",
		);

		res.render("certs", {
			title: "Certificates",
			path: "/certs",
			certs: certs,
			users: usersResult.rows,
		});
	} catch (err) {
		console.error(err);
		res.render("certs", {
			title: "Certificates - Error",
			path: "/certs",
			certs: [],
			users: [],
		});
	}
});

app.post("/certs/create", async (req, res) => {
	try {
		console.log("Creating certificate for:", req.body.name);
		const { name } = req.body;
		if (!name) throw new Error("Name is required");
		await certManager.createCert(name);
		res.redirect("/certs");
	} catch (err) {
		console.error("Cert creation error:", err);
		res.status(500).send(`Error creating certificate: ${err.message}`);
	}
});

app.get("/certs/download/ca", async (_req, res) => {
	try {
		const caPath =
			process.env.CA_CERT_PATH || "/data/certs/postgres-clients/ca.crt";
		if (require("node:fs").existsSync(caPath)) {
			res.download(caPath, "ca.crt");
		} else {
			res.status(404).send("CA Certificate not found on server.");
		}
	} catch (_err) {
		res.status(500).send("Error downloading CA");
	}
});

app.get("/certs/download/:name/:type", (req, res) => {
	const { name, type } = req.params;
	if (!["crt", "key"].includes(type))
		return res.status(400).send("Invalid type");

	const paths = certManager.getPaths(name);
	const file = type === "crt" ? paths.cert : paths.key;

	if (require("node:fs").existsSync(file)) {
		res.download(file, `${name}.${type}`);
	} else {
		res.status(404).send("File not found");
	}
});

app.post("/certs/:name/delete", async (req, res) => {
	try {
		const { name } = req.params;
		if (!name) throw new Error("Name is required");
		await certManager.deleteCert(name);
		res.redirect("/certs");
	} catch (err) {
		console.error("Cert deletion error:", err);
		res.status(500).send(`Error deleting certificate: ${err.message}`);
	}
});

app.get("/status", async (_req, res) => {
	try {
		// 1. Check if logging is enabled (table exists)
		const tableCheck = await db.query(
			"SELECT to_regclass('public.postgres_log') as exists",
		);
		const loggingEnabled = !!tableCheck.rows[0].exists;

		// 2. Count insecure users (password/trust without client cert)
		// Using pg_hba_file_rules (available in Pg 10+)
		let insecureUserCount = 0;
		try {
			// Logic: Find rules that are NOT 'local' (network), NOT using 'cert' auth,
			// and do NOT have clientcert=verify-full/verify-ca in options.
			// Then count users affected by these rules.
			const userCountResult = await db.query(`
                WITH insecure_rules AS (
                    SELECT * 
                    FROM pg_hba_file_rules 
                    WHERE type IN ('host', 'hostssl')
                      AND auth_method NOT IN ('cert', 'reject')
                      AND (options IS NULL OR NOT (
                          'clientcert=verify-full' = ANY(options) OR 
                          'clientcert=verify-ca' = ANY(options) OR
                          'clientcert=1' = ANY(options)
                      ))
                      AND error IS NULL
                ),
                affected_users AS (
                    SELECT r.rolname 
                    FROM pg_roles r
                    JOIN insecure_rules ir ON (
                        ir.user_name IS NULL OR -- Should not happen for valid rules usually
                        'all' = ANY(ir.user_name) OR 
                        r.rolname = ANY(ir.user_name) OR
                        (
                          -- Handle group roles marked with +
                          EXISTS (
                            SELECT 1 FROM unnest(ir.user_name) un(n)
                            WHERE n LIKE '+%' 
                            AND pg_has_role(r.oid, substr(n, 2), 'MEMBER')
                          )
                        )
                    )
                    WHERE r.rolcanlogin = true
                )
                SELECT count(DISTINCT rolname) FROM affected_users;
            `);
			insecureUserCount = parseInt(userCountResult.rows[0].count, 10);
		} catch (e) {
			console.warn("Could not calculate insecure users:", e.message);
			// Fallback or just show 0/error?
			// If pg_hba_file_rules doesn't exist, we can't easily know.
		}

		res.render("status", {
			title: "System Status",
			path: "/status",
			loggingEnabled,
			insecureUserCount,
		});
	} catch (err) {
		console.error(err);
		res.render("status", {
			title: "System Status - Error",
			path: "/status",
			loggingEnabled: false,
			insecureUserCount: 0,
		});
	}
});

// Backup Routes
const backupManager = require("./backup");

app.get("/backups", async (_req, res) => {
	// Render page immediately with loading state - all data fetched async via JS
	res.render("backups", {
		title: "Backups",
		path: "/backups",
		loading: true,
		formatBytes: backupManager.formatBytes,
		backupState: backupManager.getBackupState(),
	});
});

// HTML fragment endpoint for backup content (loaded asynchronously)
app.get("/backups/fragment", async (_req, res) => {
	try {
		const status = await backupManager.getSystemStatus();
		const logs = backupManager.getRecentLogs(50);
		const pgLogs = backupManager.getPostgresLogs({
			limit: 100,
			archiveOnly: true,
		});

		res.render("backups-content", {
			status,
			logs: logs.success ? logs.logs : [],
			pgLogs: pgLogs.success ? pgLogs.logs : [],
			formatBytes: backupManager.formatBytes,
		});
	} catch (err) {
		console.error("Fragment render error:", err);
		res
			.status(500)
			.send(
				`<div class="error-banner"><div class="error-header"><i data-lucide="alert-circle"></i><span>Error</span></div><div class="error-simple">${err.message}</div></div>`,
			);
	}
});

// API endpoint for logs (loaded asynchronously)
app.get("/backups/logs", (_req, res) => {
	try {
		const logs = backupManager.getRecentLogs(50);
		const pgLogs = backupManager.getPostgresLogs({
			limit: 100,
			archiveOnly: true,
		});
		res.json({
			logs: logs.success ? logs.logs : [],
			pgLogs: pgLogs.success ? pgLogs.logs : [],
		});
	} catch (err) {
		res.status(500).json({ error: err.message, logs: [], pgLogs: [] });
	}
});

// SSE endpoint for backup state updates (no compression for this route)
app.get("/backups/events", (req, res) => {
	// Disable compression for SSE
	res.setHeader("Content-Type", "text/event-stream");
	res.setHeader("Cache-Control", "no-cache, no-transform");
	res.setHeader("Connection", "keep-alive");
	res.setHeader("X-Accel-Buffering", "no"); // Disable nginx buffering
	res.setHeader("Content-Encoding", "identity"); // Disable compression

	// Flush headers immediately
	res.flushHeaders();

	// Helper to write and flush
	const sendEvent = (data) => {
		res.write(`data: ${JSON.stringify(data)}\n\n`);
		// Flush if compression middleware added flush method
		if (res.flush) res.flush();
	};

	// Send initial state
	const initialState = backupManager.getBackupState();
	sendEvent(initialState);

	// Listen for state changes
	const onStateChange = (state) => {
		sendEvent(state);
	};

	backupManager.backupEvents.on("stateChange", onStateChange);

	// Send heartbeat every 30 seconds to keep connection alive
	const heartbeat = setInterval(() => {
		res.write(": heartbeat\n\n");
		if (res.flush) res.flush();
	}, 30000);

	// Clean up on client disconnect
	req.on("close", () => {
		backupManager.backupEvents.off("stateChange", onStateChange);
		clearInterval(heartbeat);
	});
});

// Get current backup state (for polling fallback)
app.get("/backups/state", (_req, res) => {
	res.json(backupManager.getBackupState());
});

app.post("/backups/run", async (req, res) => {
	try {
		const { type } = req.body;
		const validTypes = ["full", "diff", "incr"];

		if (!validTypes.includes(type)) {
			return res
				.status(400)
				.json({ success: false, error: "Invalid backup type" });
		}

		const result = await backupManager.runBackup(type);

		if (result.success) {
			res.json({ success: true, started: true, type });
		} else {
			res.status(409).json({ success: false, error: result.error });
		}
	} catch (err) {
		console.error("Backup run error:", err);
		res.status(500).json({ success: false, error: err.message });
	}
});

app.get("/backups/info", async (_req, res) => {
	try {
		const status = await backupManager.getSystemStatus();
		res.json(status);
	} catch (err) {
		res.status(500).json({ error: err.message });
	}
});

app.get("/backups/config", (_req, res) => {
	try {
		const configContent = backupManager.generateConfig();
		res.type("text/plain").send(configContent);
	} catch (err) {
		res.status(500).send(`Error generating config: ${err.message}`);
	}
});

app.post("/backups/config", async (_req, res) => {
	const renderError = async (errorMsg) => {
		const status = await backupManager.getSystemStatus().catch(() => null);
		res.status(500).render("backups", {
			title: "Backups",
			path: "/backups",
			status,
			error: errorMsg,
			formatBytes: backupManager.formatBytes,
		});
	};

	try {
		const result = backupManager.writeConfig();
		if (result.success) {
			res.redirect("/backups");
		} else {
			await renderError(`Failed to create config file: ${result.error}`);
		}
	} catch (err) {
		console.error("Config write error:", err);
		await renderError(`Error creating config file: ${err.message}`);
	}
});

app.post("/backups/stanza-create", async (req, res) => {
	const renderError = async (errorMsg) => {
		const status = await backupManager.getSystemStatus().catch(() => null);
		res.status(500).render("backups", {
			title: "Backups",
			path: "/backups",
			status,
			error: errorMsg,
			formatBytes: backupManager.formatBytes,
		});
	};

	try {
		const noOnline = req.body.noOnline === "true" || req.body.noOnline === "1";
		const result = await backupManager.createStanza({ noOnline });
		if (result.success) {
			res.redirect("/backups");
		} else {
			await renderError(`Stanza creation failed: ${result.error}`);
		}
	} catch (err) {
		console.error("Stanza creation error:", err);
		await renderError(`Error creating stanza: ${err.message}`);
	}
});

app.post("/backups/check", async (_req, res) => {
	try {
		const result = await backupManager.runCheck();
		res.json(result);
	} catch (err) {
		res.status(500).json({ success: false, error: err.message });
	}
});

app.get("/backups/postgres-status", async (_req, res) => {
	try {
		const status = await backupManager.checkPostgresRunning();
		res.json(status);
	} catch (err) {
		console.error("Postgres status check error:", err);
		res.status(500).json({ running: false, error: err.message });
	}
});

app.post("/backups/restore", async (req, res) => {
	try {
		const { backupLabel } = req.body;

		if (!backupLabel) {
			return res
				.status(400)
				.json({ success: false, error: "Backup label is required" });
		}

		const result = await backupManager.restoreBackup(backupLabel);

		if (result.success) {
			res.json({
				success: true,
				message: `Successfully restored from backup ${backupLabel}`,
				backupLabel,
			});
		} else {
			res
				.status(500)
				.json({ success: false, error: result.error, backupLabel });
		}
	} catch (err) {
		console.error("Restore error:", err);
		res.status(500).json({ success: false, error: err.message });
	}
});

// Get backup scheduler status
app.get("/backups/scheduler", (_req, res) => {
	const scheduler = require("./scheduler");
	res.json(scheduler.getSchedulerStatus());
});

// Get backup history
app.get("/backups/history", (_req, res) => {
	try {
		const limit = req.query.limit ? parseInt(req.query.limit, 10) : 50;
		const history = backupManager.getHistory(limit);
		res.json({ success: true, history });
	} catch (err) {
		res.status(500).json({ success: false, error: err.message, history: [] });
	}
});

app.post("/status/enable-logging", async (_req, res) => {
	try {
		const initSqlPath = path.join(__dirname, "../postgres-config/init.sql");
		const sqlContent = require("node:fs").readFileSync(initSqlPath, "utf8");

		// Extract the logging part
		const marker = "-- Setup Logging Table";
		const markerIndex = sqlContent.indexOf(marker);

		if (markerIndex === -1) {
			throw new Error("Could not find logging setup section in init.sql");
		}

		const loggingSql = sqlContent.substring(markerIndex);

		// Execute statements
		// We'll split by semicolon, but need to be careful about splitting.
		// The file seems to have simple statements.
		// We might want to wrap in transaction or execute one by one.
		// Let's execute one by one.
		const statements = loggingSql
			.split(";")
			.map((s) => s.trim())
			.filter((s) => s.length > 0);

		for (const stmt of statements) {
			// Need to handle potential "already exists" errors if re-running partially
			try {
				// If it's CREATE FOREIGN TABLE or SERVER, we might want to DROP first to be clean
				// or just rely on the error if it exists.
				// The init.sql uses CREATE EXTENSION IF NOT EXISTS (safe)
				// But CREATE SERVER pglog ... will fail if exists.
				// We'll catch and ignore specific errors?

				// Let's modify the statement slightly if needed, or just run it.
				await db.query(stmt);
			} catch (e) {
				// If "already exists", we can ignore?
				if (e.code === "42710") {
					// duplicate_object (e.g. server exists)
					console.log(
						"Object already exists, skipping:",
						stmt.substring(0, 50),
					);
				} else if (e.code === "42704") {
					// undefined_object
					// ignore
					throw e;
				} else {
					console.warn(
						`Error running statement: ${stmt.substring(0, 50)}...`,
						e.message,
					);
					// For now continuing might be risky, but if it's just 'relation exists' it's fine.
					if (!e.message.includes("already exists")) {
						throw e;
					}
				}
			}
		}

		res.redirect("/status");
	} catch (err) {
		console.error(err);
		res.status(500).send(`Error enabling logging: ${err.message}`);
	}
});

// Initialize backup scheduler
const scheduler = require("./scheduler");
scheduler.initScheduler();

// Graceful shutdown handler
process.on("SIGTERM", () => {
	console.log("SIGTERM signal received: closing HTTP server");
	scheduler.stopScheduler();
	process.exit(0);
});

process.on("SIGINT", () => {
	console.log("SIGINT signal received: closing HTTP server");
	scheduler.stopScheduler();
	process.exit(0);
});

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});

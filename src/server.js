const express = require("express");
const { Eta } = require("eta");
const path = require("node:path");
const helmet = require("helmet");
const compression = require("compression");

const app = express();
const PORT = process.env.PORT || 8780;

// Middleware
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

// IP Restriction Middleware
const ALLOWED_CIDR = "100.64.0.0/10";
const ALLOWED_LOCALS = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];

function ipToLong(ip) {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	return (
		(parseInt(parts[0], 10) << 24) |
		(parseInt(parts[1], 10) << 16) |
		(parseInt(parts[2], 10) << 8) |
		parseInt(parts[3], 10)
	);
}

function inCidr(ip, cidr) {
	const [range, bits] = cidr.split("/");
	const mask = ~(2 ** (32 - bits) - 1);
	const ipLong = ipToLong(ip);
	const rangeLong = ipToLong(range);

	if (ipLong === null || rangeLong === null) return false;

	return (ipLong & mask) === (rangeLong & mask);
}

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

	if (inCidr(clientIp, ALLOWED_CIDR)) {
		return next();
	}

	console.warn(`Blocked access from IP: ${clientIp}`);
	res
		.status(403)
		.send("Forbidden: Access allowed only from Tailscale network.");
});

// View Engine Setup
const viewDir = path.join(__dirname, "../views");
const eta = new Eta({ views: viewDir });

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

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`);
});

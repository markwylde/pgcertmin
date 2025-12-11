const { Pool } = require("pg");
const fs = require("node:fs");

// Configuration from environment variables
const config = {
	host: process.env.PGHOST || "i.puzed.com",
	port: process.env.PGPORT || 15324,
	database: process.env.PGDATABASE || "postgres", // Connect to default postgres DB for admin tasks usually
	user: process.env.PGUSER || "puzed-app",
	password: process.env.PGPASSWORD, // Might not be needed if using certs only, but pg usually wants something or ignores it.
	ssl: {
		rejectUnauthorized: true,
		ca: process.env.PGSSLROOTCERT
			? fs.readFileSync(process.env.PGSSLROOTCERT).toString()
			: undefined,
		key: process.env.PGSSLKEY
			? fs.readFileSync(process.env.PGSSLKEY).toString()
			: undefined,
		cert: process.env.PGSSLCERT
			? fs.readFileSync(process.env.PGSSLCERT).toString()
			: undefined,
	},
};

const pool = new Pool(config);

pool.on("error", (err, _client) => {
	console.error("Unexpected error on idle client", err);
	process.exit(-1);
});

module.exports = {
	query: (text, params) => pool.query(text, params),
	pool,
	config: {
		user: config.user,
		host: config.host,
		database: config.database,
	},
};

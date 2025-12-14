const fs = require("node:fs");
const path = require("node:path");
const { EventEmitter } = require("node:events");

// Metrics storage file path
const METRICS_FILE =
	process.env.METRICS_FILE || "/var/log/pgsecmin/metrics.json";
const COLLECTION_INTERVAL = 5 * 1000; // 5 seconds for more granular data
const MAX_HISTORY_HOURS = 24;
const MAX_DATA_POINTS = (MAX_HISTORY_HOURS * 60 * 60) / 5; // points for 24 hours at 5s intervals

const metricsEvents = new EventEmitter();
let metricsInterval = null;
let metricsHistory = [];
let lastStats = null;
let lastCollectionTime = null;
let db = null;

// Set the database connection (called from server.js)
function setDb(dbModule) {
	db = dbModule;
}

// Initialize metrics from file or start fresh
function initMetrics() {
	try {
		const dir = path.dirname(METRICS_FILE);
		if (!fs.existsSync(dir)) {
			fs.mkdirSync(dir, { recursive: true });
		}

		if (fs.existsSync(METRICS_FILE)) {
			const data = fs.readFileSync(METRICS_FILE, "utf8");
			metricsHistory = JSON.parse(data);
			pruneOldData();
			console.log(`Loaded ${metricsHistory.length} historical metrics`);
		}
	} catch (err) {
		console.warn("Could not load metrics history:", err.message);
		metricsHistory = [];
	}
}

// Prune data older than 24 hours
function pruneOldData() {
	const cutoff = Date.now() - MAX_HISTORY_HOURS * 60 * 60 * 1000;
	metricsHistory = metricsHistory.filter((m) => m.timestamp > cutoff);
	if (metricsHistory.length > MAX_DATA_POINTS) {
		metricsHistory = metricsHistory.slice(-MAX_DATA_POINTS);
	}
}

// Save metrics to file
function saveMetrics() {
	try {
		const dir = path.dirname(METRICS_FILE);
		if (!fs.existsSync(dir)) {
			fs.mkdirSync(dir, { recursive: true });
		}
		fs.writeFileSync(METRICS_FILE, JSON.stringify(metricsHistory));
	} catch (err) {
		console.warn("Could not save metrics:", err.message);
	}
}

// Get PostgreSQL connection stats
async function getConnectionStats() {
	try {
		const [activityResult, maxResult] = await Promise.all([
			db.query(`
				SELECT
					count(*) FILTER (WHERE state = 'active') as active,
					count(*) FILTER (WHERE state = 'idle') as idle,
					count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction,
					count(*) as total
				FROM pg_stat_activity
				WHERE backend_type = 'client backend'
			`),
			db.query(`SHOW max_connections`),
		]);

		const activity = activityResult.rows[0];
		const maxConnections = parseInt(maxResult.rows[0].max_connections, 10);

		return {
			active: parseInt(activity.active, 10),
			idle: parseInt(activity.idle, 10),
			idleInTransaction: parseInt(activity.idle_in_transaction, 10),
			total: parseInt(activity.total, 10),
			max: maxConnections,
			percent:
				Math.round((parseInt(activity.total, 10) / maxConnections) * 1000) / 10,
		};
	} catch (err) {
		console.warn("Could not get connection stats:", err.message);
		return {
			active: 0,
			idle: 0,
			idleInTransaction: 0,
			total: 0,
			max: 100,
			percent: 0,
		};
	}
}

// Get PostgreSQL database stats (for calculating rates)
async function getDatabaseStats() {
	try {
		const result = await db.query(`
			SELECT
				sum(xact_commit) as commits,
				sum(xact_rollback) as rollbacks,
				sum(tup_returned) as rows_returned,
				sum(tup_fetched) as rows_fetched,
				sum(tup_inserted) as rows_inserted,
				sum(tup_updated) as rows_updated,
				sum(tup_deleted) as rows_deleted,
				sum(blks_hit) as cache_hits,
				sum(blks_read) as disk_reads
			FROM pg_stat_database
			WHERE datname NOT LIKE 'template%'
		`);

		const row = result.rows[0];
		return {
			commits: parseInt(row.commits, 10) || 0,
			rollbacks: parseInt(row.rollbacks, 10) || 0,
			rowsReturned: parseInt(row.rows_returned, 10) || 0,
			rowsFetched: parseInt(row.rows_fetched, 10) || 0,
			rowsInserted: parseInt(row.rows_inserted, 10) || 0,
			rowsUpdated: parseInt(row.rows_updated, 10) || 0,
			rowsDeleted: parseInt(row.rows_deleted, 10) || 0,
			cacheHits: parseInt(row.cache_hits, 10) || 0,
			diskReads: parseInt(row.disk_reads, 10) || 0,
		};
	} catch (err) {
		console.warn("Could not get database stats:", err.message);
		return {
			commits: 0,
			rollbacks: 0,
			rowsReturned: 0,
			rowsFetched: 0,
			rowsInserted: 0,
			rowsUpdated: 0,
			rowsDeleted: 0,
			cacheHits: 0,
			diskReads: 0,
		};
	}
}

// Calculate cache hit ratio
function calculateCacheHitRatio(stats) {
	const total = stats.cacheHits + stats.diskReads;
	if (total === 0) return 100; // No reads yet, assume perfect
	return Math.round((stats.cacheHits / total) * 1000) / 10;
}

// Calculate rates from previous stats
function calculateRates(currentStats, currentTime) {
	if (!lastStats || !lastCollectionTime) {
		return {
			transactionsPerSec: 0,
			rowsPerSec: 0,
		};
	}

	const timeDiffSec = (currentTime - lastCollectionTime) / 1000;
	if (timeDiffSec <= 0 || timeDiffSec > 60) {
		// Invalid time difference, skip rate calculation
		return {
			transactionsPerSec: 0,
			rowsPerSec: 0,
		};
	}

	const txnDiff =
		currentStats.commits +
		currentStats.rollbacks -
		(lastStats.commits + lastStats.rollbacks);
	const rowsDiff =
		currentStats.rowsInserted +
		currentStats.rowsUpdated +
		currentStats.rowsDeleted -
		(lastStats.rowsInserted + lastStats.rowsUpdated + lastStats.rowsDeleted);

	return {
		transactionsPerSec: Math.max(
			0,
			Math.round((txnDiff / timeDiffSec) * 10) / 10,
		),
		rowsPerSec: Math.max(0, Math.round((rowsDiff / timeDiffSec) * 10) / 10),
	};
}

// Collect all metrics
async function collectMetrics() {
	if (!db) {
		console.warn("Database not initialized for metrics collection");
		return null;
	}

	const timestamp = Date.now();

	try {
		const [connections, dbStats] = await Promise.all([
			getConnectionStats(),
			getDatabaseStats(),
		]);

		const cacheHitRatio = calculateCacheHitRatio(dbStats);
		const rates = calculateRates(dbStats, timestamp);

		// Store for next rate calculation
		lastStats = dbStats;
		lastCollectionTime = timestamp;

		const metrics = {
			timestamp,
			connections: {
				active: connections.active,
				idle: connections.idle,
				total: connections.total,
				max: connections.max,
				percent: connections.percent,
			},
			transactions: {
				perSecond: rates.transactionsPerSec,
				commits: dbStats.commits,
				rollbacks: dbStats.rollbacks,
			},
			cacheHitRatio,
			rows: {
				perSecond: rates.rowsPerSec,
				inserted: dbStats.rowsInserted,
				updated: dbStats.rowsUpdated,
				deleted: dbStats.rowsDeleted,
			},
		};

		// Add to history
		metricsHistory.push(metrics);
		pruneOldData();

		// Save to file every 60 collections (5 minutes)
		if (metricsHistory.length % 60 === 0) {
			saveMetrics();
		}

		// Emit event for real-time subscribers
		metricsEvents.emit("metrics", metrics);

		return metrics;
	} catch (err) {
		console.warn("Error collecting metrics:", err.message);
		return null;
	}
}

// Start collecting metrics
function startCollecting() {
	if (metricsInterval) {
		return;
	}

	initMetrics();

	// Collect immediately
	collectMetrics();

	// Then collect at regular intervals
	metricsInterval = setInterval(collectMetrics, COLLECTION_INTERVAL);
	console.log(
		`PostgreSQL metrics collection started (every ${COLLECTION_INTERVAL / 1000}s)`,
	);
}

// Stop collecting metrics
function stopCollecting() {
	if (metricsInterval) {
		clearInterval(metricsInterval);
		metricsInterval = null;
		saveMetrics();
		console.log("Metrics collection stopped");
	}
}

// Get current metrics
async function getCurrentMetrics() {
	if (!db) {
		return {
			timestamp: Date.now(),
			connections: { active: 0, idle: 0, total: 0, max: 100, percent: 0 },
			transactions: { perSecond: 0, commits: 0, rollbacks: 0 },
			cacheHitRatio: 0,
			rows: { perSecond: 0, inserted: 0, updated: 0, deleted: 0 },
		};
	}

	const timestamp = Date.now();
	const [connections, dbStats] = await Promise.all([
		getConnectionStats(),
		getDatabaseStats(),
	]);

	const cacheHitRatio = calculateCacheHitRatio(dbStats);
	const rates = calculateRates(dbStats, timestamp);

	return {
		timestamp,
		connections: {
			active: connections.active,
			idle: connections.idle,
			total: connections.total,
			max: connections.max,
			percent: connections.percent,
		},
		transactions: {
			perSecond: rates.transactionsPerSec,
			commits: dbStats.commits,
			rollbacks: dbStats.rollbacks,
		},
		cacheHitRatio,
		rows: {
			perSecond: rates.rowsPerSec,
			inserted: dbStats.rowsInserted,
			updated: dbStats.rowsUpdated,
			deleted: dbStats.rowsDeleted,
		},
	};
}

// Get historical metrics
function getHistory(limit = null) {
	if (limit && limit > 0) {
		return metricsHistory.slice(-limit);
	}
	return [...metricsHistory];
}

// Get metrics for a specific time range
function getMetricsRange(startTime, endTime = Date.now()) {
	return metricsHistory.filter(
		(m) => m.timestamp >= startTime && m.timestamp <= endTime,
	);
}

module.exports = {
	setDb,
	startCollecting,
	stopCollecting,
	getCurrentMetrics,
	getHistory,
	getMetricsRange,
	metricsEvents,
	COLLECTION_INTERVAL,
};

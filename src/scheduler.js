const cron = require("node-cron");
const { CronExpressionParser } = require("cron-parser");
const { runBackup, isBackupRunning } = require("./backup");

// Scheduled backup jobs
const scheduledJobs = {
	full: null,
	diff: null,
	incr: null,
};

/**
 * Initialize backup scheduler with cron expressions from environment variables
 *
 * Environment variables:
 * - BACKUP_SCHEDULE_FULL: Cron expression for full backups (e.g., "0 2 * * 0" for Sundays at 2 AM)
 * - BACKUP_SCHEDULE_DIFF: Cron expression for differential backups (e.g., "0 2 * * 3" for Wednesdays at 2 AM)
 * - BACKUP_SCHEDULE_INCR: Cron expression for incremental backups (e.g., "0 2 * * 1-6" for Mon-Sat at 2 AM)
 *
 * Cron format: "minute hour day-of-month month day-of-week"
 * Examples:
 * - "0 2 * * *" - Every day at 2 AM
 * - "0 2 * * 0" - Every Sunday at 2 AM
 * - "0 *\/6 * * *" - Every 6 hours
 * - "30 3 * * 1-5" - Weekdays at 3:30 AM
 */
function initScheduler() {
	const schedules = {
		full: process.env.BACKUP_SCHEDULE_FULL,
		diff: process.env.BACKUP_SCHEDULE_DIFF,
		incr: process.env.BACKUP_SCHEDULE_INCR,
	};

	let scheduledCount = 0;

	for (const [type, schedule] of Object.entries(schedules)) {
		if (!schedule) {
			console.log(
				`No schedule configured for ${type} backups (BACKUP_SCHEDULE_${type.toUpperCase()})`,
			);
			continue;
		}

		// Validate cron expression
		if (!cron.validate(schedule)) {
			console.error(
				`Invalid cron expression for ${type} backups: "${schedule}". Skipping.`,
			);
			continue;
		}

		// Schedule the backup job
		try {
			scheduledJobs[type] = cron.schedule(schedule, async () => {
				console.log(
					`[Scheduler] Triggered ${type} backup (schedule: ${schedule})`,
				);

				// Check if a backup is already running
				if (isBackupRunning()) {
					console.warn(
						`[Scheduler] Skipping ${type} backup - another backup is already running`,
					);
					return;
				}

				// Run the backup
				try {
					const result = await runBackup(type, { trigger: "scheduled" });
					if (result.success) {
						console.log(`[Scheduler] Started ${type} backup successfully`);
					} else {
						console.error(
							`[Scheduler] Failed to start ${type} backup: ${result.error}`,
						);
					}
				} catch (err) {
					console.error(`[Scheduler] Error starting ${type} backup:`, err);
				}
			});

			console.log(
				`[Scheduler] Scheduled ${type} backups with cron: ${schedule}`,
			);
			scheduledCount++;
		} catch (err) {
			console.error(
				`[Scheduler] Failed to schedule ${type} backups:`,
				err.message,
			);
		}
	}

	if (scheduledCount === 0) {
		console.log(
			"[Scheduler] No backup schedules configured. Set BACKUP_SCHEDULE_FULL, BACKUP_SCHEDULE_DIFF, or BACKUP_SCHEDULE_INCR to enable automatic backups.",
		);
	} else {
		console.log(`[Scheduler] Initialized ${scheduledCount} backup schedule(s)`);
	}

	return scheduledJobs;
}

/**
 * Stop all scheduled backup jobs
 */
function stopScheduler() {
	let stoppedCount = 0;

	for (const [type, job] of Object.entries(scheduledJobs)) {
		if (job) {
			job.stop();
			scheduledJobs[type] = null;
			stoppedCount++;
		}
	}

	if (stoppedCount > 0) {
		console.log(`[Scheduler] Stopped ${stoppedCount} backup schedule(s)`);
	}
}

/**
 * Get status of scheduled jobs
 */
function getSchedulerStatus() {
	const schedules = {
		full: process.env.BACKUP_SCHEDULE_FULL || null,
		diff: process.env.BACKUP_SCHEDULE_DIFF || null,
		incr: process.env.BACKUP_SCHEDULE_INCR || null,
	};

	// Calculate next run times
	const nextRun = {};
	for (const [type, schedule] of Object.entries(schedules)) {
		if (schedule && cron.validate(schedule)) {
			try {
				const interval = CronExpressionParser.parse(schedule, {
					currentDate: new Date(),
					tz: "Etc/UTC",
				});
				nextRun[type] = interval.next().toDate();
			} catch (err) {
				console.error(`Failed to parse cron for ${type}:`, err.message);
				nextRun[type] = null;
			}
		} else {
			nextRun[type] = null;
		}
	}

	return {
		enabled: Object.values(scheduledJobs).some((job) => job !== null),
		schedules,
		nextRun,
		jobs: {
			full: scheduledJobs.full !== null,
			diff: scheduledJobs.diff !== null,
			incr: scheduledJobs.incr !== null,
		},
	};
}

module.exports = {
	initScheduler,
	stopScheduler,
	getSchedulerStatus,
	scheduledJobs,
};

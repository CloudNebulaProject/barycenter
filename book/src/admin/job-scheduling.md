# Job Scheduling

Barycenter's background job scheduler is built on [tokio-cron-scheduler](https://crates.io/crates/tokio-cron-scheduler), a cron-based job scheduling library that runs within the Tokio async runtime. Jobs are defined at compile time, registered during server startup, and execute automatically according to their cron expressions.

## How the Scheduler Works

### Startup

During server initialization, after the database connection is established, Barycenter:

1. Creates a `JobScheduler` instance.
2. Registers each background job with its cron expression and execution function.
3. Starts the scheduler, which runs as a background Tokio task for the lifetime of the server process.

No configuration is needed to enable the scheduler -- it starts automatically as part of the normal server boot sequence.

### Execution

When a job's cron expression matches the current time, the scheduler spawns a Tokio task that:

1. Records the start time.
2. Executes the job's cleanup query against the database.
3. Counts the number of records affected.
4. Writes an execution record to the `job_execution` table with the result.

Jobs execute asynchronously and do not block the main server or each other. If a job takes longer than expected (e.g., due to a large number of expired records), other jobs and request handling continue unaffected.

### Graceful Shutdown

When the server receives a shutdown signal, the scheduler stops accepting new job executions. Any currently running jobs are allowed to complete before the process exits.

## Cron Expression Format

Barycenter uses six-field cron expressions (with a seconds field), as supported by tokio-cron-scheduler:

```
┌──────── second (0-59)
│ ┌────── minute (0-59)
│ │ ┌──── hour (0-23)
│ │ │ ┌── day of month (1-31)
│ │ │ │ ┌ month (1-12)
│ │ │ │ │ ┌ day of week (0-6, 0 = Sunday)
│ │ │ │ │ │
* * * * * *
```

### Current Job Schedules

| Job | Cron Expression | Meaning |
|---|---|---|
| `cleanup_expired_sessions` | `0 0 * * * *` | At second 0, minute 0 of every hour |
| `cleanup_expired_refresh_tokens` | `0 30 * * * *` | At second 0, minute 30 of every hour |
| `cleanup_expired_challenges` | `0 */5 * * * *` | At second 0, every 5th minute |
| `cleanup_expired_device_codes` | `0 45 * * * *` | At second 0, minute 45 of every hour |

### Cron Expression Examples

For reference, here are common cron patterns in the six-field format:

| Expression | Meaning |
|---|---|
| `0 0 * * * *` | Every hour at :00 |
| `0 30 * * * *` | Every hour at :30 |
| `0 */5 * * * *` | Every 5 minutes |
| `0 */15 * * * *` | Every 15 minutes |
| `0 0 */2 * * *` | Every 2 hours |
| `0 0 0 * * *` | Once daily at midnight |
| `0 0 3 * * *` | Once daily at 03:00 |
| `0 0 0 * * 1` | Every Monday at midnight |

## Job Execution Tracking

Every time a job runs -- whether triggered by the cron schedule or manually via the admin API -- an execution record is written to the `job_execution` table:

| Column | Type | Description |
|---|---|---|
| `id` | `integer` | Auto-incrementing primary key |
| `job_name` | `string` | Name of the executed job |
| `started_at` | `timestamp` | When execution began |
| `completed_at` | `timestamp` | When execution finished (null if still running) |
| `success` | `boolean` | Whether the job completed without error |
| `error_message` | `string` | Error details if the job failed (null on success) |
| `records_processed` | `integer` | Number of database records affected |

This table serves as both an audit log and a monitoring data source. Query it through the admin API's `jobLogs` query or directly through the Seaography entity CRUD schema.

## Staggered Schedules

The four built-in jobs are deliberately staggered across different minutes of the hour to avoid simultaneous execution:

```
:00  cleanup_expired_sessions
:05  cleanup_expired_challenges
:10  cleanup_expired_challenges
:15  cleanup_expired_challenges
:20  cleanup_expired_challenges
:25  cleanup_expired_challenges
:30  cleanup_expired_refresh_tokens + cleanup_expired_challenges
:35  cleanup_expired_challenges
:40  cleanup_expired_challenges
:45  cleanup_expired_device_codes + cleanup_expired_challenges
:50  cleanup_expired_challenges
:55  cleanup_expired_challenges
```

The challenge cleanup runs every 5 minutes due to the short TTL of WebAuthn challenges, while the other three jobs run once per hour at different offsets. This distribution prevents database contention from multiple concurrent cleanup operations.

## Timezone

The cron scheduler operates in UTC. All timestamps in the `job_execution` table are recorded in UTC.

## Further Reading

- [Available Jobs](./available-jobs.md) -- what each job does
- [Monitoring Job Executions](./job-monitoring.md) -- querying the execution log
- [Job Management](./job-management.md) -- triggering jobs and querying logs via GraphQL
- [Background Jobs](./background-jobs.md) -- overview of the job system

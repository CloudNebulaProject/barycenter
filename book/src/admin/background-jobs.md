# Background Jobs

Barycenter runs a set of background jobs that perform periodic maintenance tasks such as cleaning up expired sessions, tokens, and challenges. These jobs start automatically when the server launches and run on a configurable schedule. The job system is built on [tokio-cron-scheduler](https://crates.io/crates/tokio-cron-scheduler) and integrates with the admin GraphQL API for on-demand triggering and monitoring.

## Overview

Background jobs handle housekeeping that would otherwise cause unbounded growth of expired records in the database. Without these jobs, the sessions, tokens, and challenges tables would accumulate stale rows over time, degrading query performance and consuming storage.

Each job:

- Runs on a cron schedule defined at compile time.
- Executes a database query that deletes records past their expiration time.
- Logs its execution result (success or failure, records processed) to the `job_execution` table.
- Can be triggered on demand via the admin API.

## Available Jobs

Barycenter ships with four built-in background jobs:

| Job | Schedule | Description |
|---|---|---|
| `cleanup_expired_sessions` | Hourly at :00 | Deletes user sessions past their expiration time |
| `cleanup_expired_refresh_tokens` | Hourly at :30 | Deletes refresh tokens past their expiration time |
| `cleanup_expired_challenges` | Every 5 minutes | Deletes WebAuthn challenges older than 5 minutes |
| `cleanup_expired_device_codes` | Hourly at :45 | Deletes expired device authorization codes |

See [Available Jobs](./available-jobs.md) for detailed descriptions of each job.

## Key Concepts

### Automatic Startup

All jobs are registered with the scheduler during server initialization and begin running immediately. No manual action is required to start the job scheduler -- it is an integral part of the server lifecycle.

### Execution Tracking

Every job execution is recorded in the `job_execution` table with a start time, completion time, success status, error message (if applicable), and a count of records processed. This provides a complete audit trail of maintenance operations.

### On-Demand Triggering

While jobs run automatically on their schedules, administrators can trigger any job immediately through the `triggerJob` mutation at `POST /admin/jobs`. This is useful for:

- Forcing a cleanup after a known batch of expirations.
- Verifying that a job executes correctly after a deployment.
- Clearing expired records before a maintenance window.

### Monitoring

Job execution logs can be queried through the admin API, filtered by job name and failure status. This supports operational monitoring and alerting on job failures.

## Architecture

```
Server Startup
    |
    v
Register Jobs with tokio-cron-scheduler
    |
    +---> cleanup_expired_sessions      (0 0 * * * *)
    +---> cleanup_expired_refresh_tokens (0 30 * * * *)
    +---> cleanup_expired_challenges     (0 */5 * * * *)
    +---> cleanup_expired_device_codes   (0 45 * * * *)
    |
    v
Scheduler runs in background (tokio task)
    |
    +---> On each trigger: execute cleanup query
    +---> Record result in job_execution table
```

## Further Reading

- [Available Jobs](./available-jobs.md) -- detailed descriptions of each background job
- [Job Scheduling](./job-scheduling.md) -- cron expressions and scheduler internals
- [Monitoring Job Executions](./job-monitoring.md) -- querying execution logs and detecting failures
- [Job Management](./job-management.md) -- admin API for triggering jobs and querying logs

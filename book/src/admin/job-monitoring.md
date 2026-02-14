# Monitoring Job Executions

Every background job execution in Barycenter is recorded in the `job_execution` table, providing a complete history of when jobs ran, whether they succeeded, how many records they processed, and what errors occurred. The admin API exposes this data through the `jobLogs` query at `POST /admin/jobs`.

## Querying Job Logs

### Basic Query

Retrieve the most recent job executions:

```graphql
{
  jobLogs(limit: 10) {
    id
    jobName
    startedAt
    completedAt
    success
    errorMessage
    recordsProcessed
  }
}
```

### Response

```json
{
  "data": {
    "jobLogs": [
      {
        "id": "42",
        "jobName": "cleanup_expired_sessions",
        "startedAt": "2026-02-14T12:00:00Z",
        "completedAt": "2026-02-14T12:00:01Z",
        "success": true,
        "errorMessage": null,
        "recordsProcessed": 15
      },
      {
        "id": "41",
        "jobName": "cleanup_expired_challenges",
        "startedAt": "2026-02-14T11:55:00Z",
        "completedAt": "2026-02-14T11:55:00Z",
        "success": true,
        "errorMessage": null,
        "recordsProcessed": 3
      }
    ]
  }
}
```

## Response Fields

| Field | Type | Description |
|---|---|---|
| `id` | `ID` | Unique identifier for this execution record. |
| `jobName` | `String` | Name of the job that was executed. |
| `startedAt` | `String` | ISO 8601 UTC timestamp when execution began. |
| `completedAt` | `String` | ISO 8601 UTC timestamp when execution finished. `null` if the job is still running. |
| `success` | `Boolean` | Whether the execution completed without error. |
| `errorMessage` | `String` | Error details if the execution failed. `null` on success. |
| `recordsProcessed` | `Int` | Number of records affected by the job (e.g., expired sessions deleted). |

## Filtering

### By Job Name

Narrow results to a specific job:

```graphql
{
  jobLogs(jobName: "cleanup_expired_sessions", limit: 20) {
    id
    startedAt
    completedAt
    success
    recordsProcessed
  }
}
```

### Failures Only

Show only executions that failed:

```graphql
{
  jobLogs(onlyFailures: true) {
    id
    jobName
    startedAt
    errorMessage
  }
}
```

### Combined Filters

Filter by both job name and failure status:

```graphql
{
  jobLogs(jobName: "cleanup_expired_refresh_tokens", onlyFailures: true, limit: 10) {
    id
    startedAt
    completedAt
    errorMessage
  }
}
```

## Query Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `jobName` | `String` | `null` (all jobs) | Filter to a specific job by name. |
| `limit` | `Int` | `100` | Maximum number of entries to return. |
| `onlyFailures` | `Boolean` | `false` | When `true`, return only failed executions. |

Results are ordered by `startedAt` descending (most recent first).

## curl Examples

```bash
# Get the 10 most recent job executions
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ jobLogs(limit: 10) { id jobName startedAt completedAt success errorMessage recordsProcessed } }"
  }' | jq .

# Get failures only
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ jobLogs(onlyFailures: true) { id jobName startedAt errorMessage } }"
  }' | jq .

# Get execution history for a specific job
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ jobLogs(jobName: \"cleanup_expired_challenges\", limit: 5) { startedAt success recordsProcessed } }"
  }' | jq .
```

## Monitoring Strategies

### Health Checks

Verify that jobs are running on schedule by checking the most recent execution time. If the most recent execution of a job is significantly older than its schedule interval, the scheduler may have stalled.

```graphql
{
  sessions: jobLogs(jobName: "cleanup_expired_sessions", limit: 1) {
    startedAt
    success
  }
  challenges: jobLogs(jobName: "cleanup_expired_challenges", limit: 1) {
    startedAt
    success
  }
}
```

For example, if `cleanup_expired_challenges` normally runs every 5 minutes but the most recent execution was 30 minutes ago, investigate the server health.

### Failure Alerting

Periodically query for recent failures and feed the results into your alerting system:

```bash
# Check for any failures in the last hour (pipe to your alerting tool)
FAILURES=$(curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{"query": "{ jobLogs(onlyFailures: true, limit: 1) { id } }"}' \
  | jq '.data.jobLogs | length')

if [ "$FAILURES" -gt 0 ]; then
  echo "ALERT: Background job failures detected"
fi
```

### Tracking Cleanup Volume

Monitor `recordsProcessed` to understand how many expired records are being cleaned up. A sudden increase may indicate:

- A spike in user activity generating more sessions and tokens.
- A configuration change that shortened token lifetimes.
- An issue causing tokens to not be cleaned up on time (backlog).

A consistently zero `recordsProcessed` for a job is normal -- it means no records had expired since the last run.

### Alternative: Seaography Entity Query

The `job_execution` table is also available through the Seaography entity CRUD schema at `POST /admin/graphql`, which provides more advanced filtering options:

```graphql
{
  jobExecution {
    findMany(
      filter: {
        success: { eq: false }
        startedAt: { gt: "2026-02-14T00:00:00Z" }
      }
      orderBy: { startedAt: DESC }
    ) {
      nodes {
        id
        jobName
        startedAt
        errorMessage
      }
    }
  }
}
```

This approach is useful when you need date-range filtering or more complex query logic than the `jobLogs` query provides.

## Further Reading

- [Job Management](./job-management.md) -- triggering jobs and the full `jobLogs` query reference
- [Available Jobs](./available-jobs.md) -- what each job does and its schedule
- [Job Scheduling](./job-scheduling.md) -- how the cron scheduler operates
- [Entity CRUD (Seaography)](./entity-crud.md) -- querying job_execution via the entity schema

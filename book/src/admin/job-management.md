# Job Management

The job management schema at `POST /admin/jobs` provides queries and mutations for controlling Barycenter's background job system. You can trigger jobs on demand, list available jobs and their schedules, and query execution history with filtering.

## Triggering a Job

Use the `triggerJob` mutation to run a background job immediately, without waiting for its next scheduled execution.

### Mutation

```graphql
mutation {
  triggerJob(jobName: "cleanup_expired_sessions") {
    success
    message
    jobName
  }
}
```

### Response

```json
{
  "data": {
    "triggerJob": {
      "success": true,
      "message": "Job cleanup_expired_sessions triggered successfully",
      "jobName": "cleanup_expired_sessions"
    }
  }
}
```

If the job name does not match any registered job, the mutation returns an error:

```json
{
  "data": {
    "triggerJob": {
      "success": false,
      "message": "Unknown job: nonexistent_job",
      "jobName": "nonexistent_job"
    }
  }
}
```

### curl Example

```bash
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { triggerJob(jobName: \"cleanup_expired_sessions\") { success message jobName } }"
  }' | jq .
```

## Listing Available Jobs

The `availableJobs` query returns all registered background jobs with their descriptions and cron schedules.

### Query

```graphql
{
  availableJobs {
    name
    description
    schedule
  }
}
```

### Response

```json
{
  "data": {
    "availableJobs": [
      {
        "name": "cleanup_expired_sessions",
        "description": "Clean up expired user sessions",
        "schedule": "0 0 * * * *"
      },
      {
        "name": "cleanup_expired_refresh_tokens",
        "description": "Clean up expired refresh tokens",
        "schedule": "0 30 * * * *"
      },
      {
        "name": "cleanup_expired_challenges",
        "description": "Clean up expired WebAuthn challenges",
        "schedule": "0 */5 * * * *"
      },
      {
        "name": "cleanup_expired_device_codes",
        "description": "Clean up expired device authorization codes",
        "schedule": "0 45 * * * *"
      }
    ]
  }
}
```

### curl Example

```bash
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{"query": "{ availableJobs { name description schedule } }"}' | jq .
```

## Querying Job Execution Logs

The `jobLogs` query retrieves execution history for background jobs. Results are ordered by start time, most recent first.

### Query

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

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `jobName` | `String` | all jobs | Filter logs to a specific job by name. |
| `limit` | `Int` | `100` | Maximum number of log entries to return. |
| `onlyFailures` | `Boolean` | `false` | When `true`, return only failed executions. |

### Filter by Job Name

```graphql
{
  jobLogs(jobName: "cleanup_expired_sessions", limit: 5) {
    id
    jobName
    startedAt
    completedAt
    success
    recordsProcessed
  }
}
```

### Filter for Failures Only

```graphql
{
  jobLogs(onlyFailures: true, limit: 20) {
    id
    jobName
    startedAt
    completedAt
    success
    errorMessage
  }
}
```

### Response Fields

| Field | Type | Description |
|---|---|---|
| `id` | `ID` | Unique identifier for this execution record. |
| `jobName` | `String` | Name of the job that was executed. |
| `startedAt` | `String` | ISO 8601 timestamp when execution began. |
| `completedAt` | `String` | ISO 8601 timestamp when execution finished. May be `null` if still running. |
| `success` | `Boolean` | Whether the execution completed successfully. |
| `errorMessage` | `String` | Error details if the execution failed. `null` on success. |
| `recordsProcessed` | `Int` | Number of records affected (e.g., expired sessions deleted). |

### curl Example

```bash
# Get the last 10 job executions
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ jobLogs(limit: 10) { id jobName startedAt completedAt success errorMessage recordsProcessed } }"
  }' | jq .

# Get only failures for a specific job
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ jobLogs(jobName: \"cleanup_expired_sessions\", onlyFailures: true) { id startedAt errorMessage } }"
  }' | jq .
```

## Combining Queries

GraphQL allows multiple queries in a single request:

```graphql
{
  availableJobs {
    name
    schedule
  }
  jobLogs(limit: 5, onlyFailures: true) {
    jobName
    startedAt
    errorMessage
  }
}
```

## Further Reading

- [Available Jobs](./available-jobs.md) -- detailed descriptions of each background job
- [Job Scheduling](./job-scheduling.md) -- how the cron scheduler works
- [Monitoring Job Executions](./job-monitoring.md) -- strategies for monitoring job health
- [User 2FA Management](./user-2fa.md) -- the other custom schema at `/admin/jobs`

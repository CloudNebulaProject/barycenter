# Available Jobs

Barycenter includes four built-in background jobs that perform periodic cleanup of expired database records. Each job targets a specific table and removes rows that have passed their expiration time.

## Job Reference

| Job Name | Description | Cron Schedule | Frequency |
|---|---|---|---|
| `cleanup_expired_sessions` | Clean up expired user sessions | `0 0 * * * *` | Hourly at :00 |
| `cleanup_expired_refresh_tokens` | Clean up expired refresh tokens | `0 30 * * * *` | Hourly at :30 |
| `cleanup_expired_challenges` | Clean up expired WebAuthn challenges | `0 */5 * * * *` | Every 5 minutes |
| `cleanup_expired_device_codes` | Clean up expired device authorization codes | `0 45 * * * *` | Hourly at :45 |

## Job Details

### cleanup_expired_sessions

**Schedule**: Hourly at the top of the hour.

Deletes rows from the `sessions` table where the `expires_at` timestamp is in the past. User sessions have a configurable lifetime; once expired, they cannot be used for authentication and serve no further purpose.

Keeping expired sessions in the database does not affect correctness (expired sessions are rejected at authentication time), but removing them reduces table size and improves query performance for session lookups.

**Records processed**: The number of expired sessions deleted in each run.

### cleanup_expired_refresh_tokens

**Schedule**: Hourly at 30 minutes past the hour.

Deletes rows from the `refresh_tokens` table where the expiration timestamp has passed. Refresh tokens have a longer lifetime than access tokens but still expire eventually. Expired refresh tokens cannot be used to obtain new access tokens.

This job also removes refresh tokens that have been rotated and are no longer the current token in the rotation chain, provided they have passed their grace period.

**Records processed**: The number of expired refresh tokens deleted in each run.

### cleanup_expired_challenges

**Schedule**: Every 5 minutes.

Deletes rows from the `webauthn_challenges` table where the challenge is older than 5 minutes. WebAuthn challenges are ephemeral -- they are created at the start of a registration or authentication ceremony and must be consumed within a short window. Unclaimed challenges (e.g., from abandoned login attempts) accumulate and should be cleaned up frequently.

This job runs more frequently than the others because challenges have a very short TTL and can accumulate rapidly in high-traffic deployments.

**Records processed**: The number of expired challenges deleted in each run.

### cleanup_expired_device_codes

**Schedule**: Hourly at 45 minutes past the hour.

Deletes rows from the device authorization codes table where the expiration timestamp has passed. Device authorization codes are issued during the [Device Authorization Grant](../oidc/grant-device-authorization.md) flow and have a limited lifetime for the user to complete the authorization on a secondary device. Codes that are not used within this window expire and should be removed.

**Records processed**: The number of expired device codes deleted in each run.

## Querying Available Jobs

You can retrieve this information programmatically via the admin API:

```graphql
{
  availableJobs {
    name
    description
    schedule
  }
}
```

```bash
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{"query": "{ availableJobs { name description schedule } }"}' | jq .
```

## Triggering Jobs Manually

Any job can be triggered outside its normal schedule using the `triggerJob` mutation:

```graphql
mutation {
  triggerJob(jobName: "cleanup_expired_sessions") {
    success
    message
    jobName
  }
}
```

See [Job Management](./job-management.md) for full details on triggering and monitoring.

## Further Reading

- [Job Scheduling](./job-scheduling.md) -- cron expression format and scheduler behavior
- [Monitoring Job Executions](./job-monitoring.md) -- querying execution history
- [Job Management](./job-management.md) -- admin API operations for jobs
- [Background Jobs](./background-jobs.md) -- overview of the job system

# Harness checkout project-status gate — operations guide

Date: 2026-09-09
Origin issue: ATC-197 "Run harness starts issues whose project status is backlog"
Author: Alpha Technology CTO agent
Status: **staged, not deployed.** No agent deploys this change. The board deploys it.

## 1. What was wrong

The run harness claims an issue for a run by calling the issue service `checkout`
function directly. It does not go through `POST /api/issues/{id}/checkout`. Two
consequences followed.

1. The harness claimed an issue on the issue row's own status alone. It never
   read the status of the project that the issue belongs to. An operator parks a
   project by moving its status out of `in_progress`. The harness ignored that
   signal.
2. The harness accepted `backlog` as a claimable issue status. `backlog` means
   "not scheduled yet". The harness pulled such an issue straight to
   `in_progress`.
3. The route writes an `issue.checked_out` activity record. The harness path does
   not go through the route, so it wrote no record. A harness transition was
   invisible in `GET /api/issues/{id}/activity`.

Observed case: issue ATC-110 sits in the `AuthorAgent` project. That project has
status `backlog`. The issue also had status `backlog`. At 2026-09-09 02:56:18 UTC
the harness set the issue to `in_progress`, set `checkoutRunId` and
`executionRunId`, and set `startedAt`. No activity record exists for that
transition.

## 2. What the change does

### 2.1 New module: `server/src/services/harness-checkout-gate.ts`

Pure predicates with no database or service imports:

- `isProjectStatusEligibleForHarnessCheckout(projectStatus, hasProject)` returns
  true only when the project status is `in_progress`, or when the issue belongs
  to no project.
- `isIssueStatusEligibleForHarnessCheckout(issueStatus)` returns false for
  `backlog`.
- `resolveHarnessCheckoutBlock(...)` returns the block reason or `null`.
- `HARNESS_AUTO_CHECKOUT_ISSUE_STATUSES` is `["todo", "blocked"]`. It replaces
  the previous literal `["todo", "backlog", "blocked"]`.

The gate **fails closed**. If the issue has a project and the project status does
not load, the gate blocks the claim. This closes the known list-endpoint trap:
`GET /api/companies/{companyId}/issues` does not populate a project object, so a
caller that reads project status from a list response reads an empty field. The
change does not read project status from a list response at all. It reads the
`projects` row by id, in `getProjectStatusForIssue`.

### 2.2 `server/src/services/heartbeat.ts`

- `shouldAutoCheckoutIssueForWake` no longer accepts `backlog`, and now takes
  `issueHasProject` and `issueProjectStatus`.
- The auto-checkout call site resolves the gate before it claims, and passes
  `["todo", "blocked"]` as the expected statuses.
- New helper `getProjectStatusForIssue(companyId, projectId)` reads the project
  row by id.
- New helper `recordHarnessCheckoutActivity(...)` writes the activity record for
  every harness checkout decision. It never throws. A failed audit write is
  logged as a warning and does not fail the run.

### 2.3 Activity records the harness now writes

| Action | When |
|---|---|
| `issue.checked_out` with `details.source = "harness_auto_checkout"` | The harness claimed the issue on a wake. |
| `issue.checked_out` with `details.source = "harness_interaction_continuation"` | The harness re-claimed the issue to resume after an interaction response. |
| `issue.harness_checkout_skipped` | The gate blocked the claim. `details.reason` is `project_status_not_in_progress` or `issue_status_backlog`. |

Every record carries `details.actor = "run_harness"`, the issue status before the
transition, the project id, and the project status. `GET /api/issues/{id}/activity`
returns all of them; that endpoint applies no action filter.

### 2.4 Liveness evidence exclusion — read this one closely

`issue.checked_out` and `issue.harness_checkout_skipped` are added to
`LIVENESS_BOOKKEEPING_ACTIVITY_ACTIONS` in `heartbeat.ts`.

This is not cosmetic. The run-liveness classifier counts activity records
attributed to a run as `activityEventsCreated`, and any non-zero count is
"concrete action evidence". Without this exclusion, the new harness activity
record makes **every** harness-claimed run look like it produced concrete
action. The classifier then returns `advanced` instead of `plan_only` or
`empty_response`, and the recovery service stops enqueueing liveness
continuations. The existing test
`heartbeat-process-recovery.test.ts > classifies actionable plan-only recovery
and enqueues one liveness continuation` catches this exactly.

The exclusion is by action name, so it also applies to the `issue.checked_out`
record written by `POST /api/issues/{id}/checkout`. That is a deliberate
behaviour change and the board should know about it: a run whose only recorded
activity was checking an issue out now classifies as `empty_response` rather
than `advanced`. That reading is the correct one — checking an issue out is
bookkeeping, not work on the issue — and it errs toward firing recovery rather
than suppressing it. The two entries already in that list,
`environment.lease_acquired` and `environment.lease_released`, are the same kind
of bookkeeping.

### 2.5 `ui/src/lib/activity-format.ts`

Display labels for the new `issue.harness_checkout_skipped` action.

### 2.6 Test-helper extraction

`createControlledGatewayServer` moved from
`server/src/__tests__/heartbeat-comment-wake-batching.test.ts` to
`server/src/__tests__/helpers/controlled-gateway-server.ts`. The body is
unchanged. Both test files import it.

## 3. Scope limits — read before you deploy

Three limits are deliberate. Each one is a decision, not an oversight.

**The gate covers the harness auto-checkout path only.** It does not change
`POST /api/issues/{id}/checkout`. A person or an agent that explicitly checks out
an issue still can. The defect was automated selection, and blocking the explicit
route would also block an operator who intends to start a parked issue by hand.

**The gate does not cover the interaction-continuation checkout.** That path
resumes a run on an issue that is already `in_progress` after a person answers an
interaction. It is not the path that starts a parked issue. Gating it would strand
a live run whose project was parked mid-flight. That path now writes an activity
record, which it did not before.

**The gate does not clear `executionRunId`.** The run-dispatch lock that binds a
live run to an issue is set separately from the checkout, and it is released when
the run ends. A blocked wake therefore still shows a transient `executionRunId` on
the issue while that run is alive. The issue's own `status` does not change and
`checkoutRunId` stays null. If the board wants the execution lock gated too, that
is a separate change to run dispatch with its own stranding risk.

## 4. Blast radius

The gate refuses a harness claim whenever the project status is not
`in_progress`. **The `projects.status` column defaults to `backlog`.** Any project
created without an explicit status therefore parks its issues from the harness's
point of view. Before deploying, check how many active projects in this instance
are not `in_progress`:

```sql
select status, count(*) from projects group by status;
```

An issue with `project_id = null` is unaffected.

The observable change for an affected wake: the agent is still woken, the wake
payload no longer says "checkout: already claimed by the harness for this run",
and the issue keeps its own status.

## 5. Verification performed

Run from the repository root, in `paperclip-control-plane/server`:

```sh
pnpm exec tsc --noEmit
pnpm exec vitest run src/__tests__/harness-checkout-gate.test.ts \
  src/__tests__/heartbeat-auto-checkout.test.ts \
  src/__tests__/heartbeat-harness-checkout-project-gate.test.ts
```

Results on 2026-09-09, against the final state of the branch:

- `tsc --noEmit`: **0 errors.** This requires `@paperclipai/plugin-sdk` to be
  built first (`pnpm --filter @paperclipai/plugin-sdk build`). Without that build
  the server reports 140 pre-existing `plugin-sdk` resolution errors that have
  nothing to do with this change.
- `harness-checkout-gate.test.ts`, `heartbeat-auto-checkout.test.ts`,
  `heartbeat-harness-checkout-project-gate.test.ts`,
  `heartbeat-comment-wake-batching.test.ts`: **38 tests passed.** The
  project-gate file runs a real heartbeat run against embedded Postgres and a
  stub gateway, and asserts the three acceptance criteria end to end.
- `heartbeat-process-recovery.test.ts`: **128 tests passed.** This suite caught
  the liveness-evidence regression described in section 2.4. It failed on this
  branch and passed on the unmodified base commit `e200104` before the exclusion
  was added, which is how the regression was attributed.
- `activity-service`, `disposition-repair`, `productivity-review-service`,
  `run-continuations`, `run-liveness`, `issue-recovery-actions`,
  `agent-live-run-routes`, `recovery-classifiers`, `heartbeat-list`:
  **131 tests passed.** These are the suites that read liveness evidence.

The full server suite was not run to completion in this environment. The suites
above were selected because they cover the harness checkout path, the activity
log, and every consumer of liveness evidence.

`pnpm --filter @paperclipai/server typecheck` does not complete in this
environment. Its `prepare:runner-vendor` step builds a Rust binary and `cargo` is
not installed here. That is an environment gap, not a defect in this change.

## 6. Deploy procedure

This is a control-plane change. The 2026-09-07 board decision permits an agent to
write, test, and stage it. No agent deploys it.

1. Apply the patch to a checkout of `github.com/paperclipai/paperclip`. The
   staged branch is `atc-197-harness-checkout-project-status-gate`, and the
   patch file is attached to issue ATC-197.
2. Build the plugin SDK, then typecheck and test:
   ```sh
   pnpm install
   pnpm --filter @paperclipai/plugin-sdk build
   cd server && pnpm exec tsc --noEmit
   pnpm exec vitest run src/__tests__/harness-checkout-gate.test.ts \
     src/__tests__/heartbeat-auto-checkout.test.ts \
     src/__tests__/heartbeat-harness-checkout-project-gate.test.ts \
     src/__tests__/heartbeat-comment-wake-batching.test.ts \
     src/__tests__/heartbeat-process-recovery.test.ts
   ```
   Do not skip `heartbeat-process-recovery.test.ts`. It is the suite that guards
   the liveness-evidence behaviour in section 2.4.
3. Run the project-status count in section 4 against the production database and
   read the result before you continue.
4. Build and restart the Paperclip server. No database migration is needed. This
   change adds no column, no table, and no index.
5. After the restart, confirm the gate is live. Wake an agent on an issue in a
   project whose status is not `in_progress`, then read the activity log:
   ```sh
   curl -s -H "Authorization: Bearer $KEY" \
     "$BASE/api/issues/<issueId>/activity" | grep harness_checkout_skipped
   ```
   A record with `"reason":"project_status_not_in_progress"` confirms it.

## 7. Rollback

Revert the commit and restart the server. There is no data migration and no
persisted state that the change creates, other than activity-log rows. Those rows
are additive and harmless if the change is reverted.

/**
 * Harness checkout gate.
 *
 * The run harness claims an issue for a wake without going through
 * `POST /api/issues/:id/checkout`. That path therefore does not inherit the
 * route-level guards, and it used to claim an issue purely on the issue row's
 * own status. Two states must stop the claim:
 *
 * 1. The issue's project is not being worked. An operator parks a project by
 *    setting its status to something other than `in_progress`. A parked project
 *    is a deliberate stop signal, and the harness must honour it.
 * 2. The issue itself sits in `backlog`. `backlog` means "not scheduled yet".
 *    Pulling a `backlog` row straight to `in_progress` skips the scheduling
 *    step that `todo` represents.
 *
 * The predicates live in their own module, free of database and service
 * imports, so they are unit-testable in isolation and so both harness call
 * sites in `heartbeat.ts` share one definition.
 */

/**
 * The only project status under which the harness may claim an issue.
 *
 * `PROJECT_STATUSES` is `backlog | planned | in_progress | completed |
 * cancelled`. Every value other than `in_progress` means the project is not
 * being worked right now, so the harness must leave its issues alone.
 */
export const HARNESS_CHECKOUT_ALLOWED_PROJECT_STATUS = "in_progress";

/** Issue statuses the harness may pull into `in_progress` on a wake. */
export const HARNESS_AUTO_CHECKOUT_ISSUE_STATUSES = [
  "todo",
  "blocked",
] as const;

export type HarnessCheckoutBlockReason =
  | "project_status_not_in_progress"
  | "issue_status_backlog";

/**
 * Decide whether the project a wake's issue belongs to permits a harness claim.
 *
 * An issue with no project is unaffected: `projectId` is nullable, and an issue
 * outside every project has no project status to honour.
 */
export function isProjectStatusEligibleForHarnessCheckout(
  projectStatus: string | null | undefined,
  hasProject: boolean,
): boolean {
  if (!hasProject) return true;
  // A project row that the harness could not read is treated as ineligible.
  // Failing closed here is deliberate: the cost of skipping one wake is a
  // delayed issue, and the cost of failing open is the defect this gate exists
  // to close.
  if (typeof projectStatus !== "string") return false;
  return projectStatus.trim() === HARNESS_CHECKOUT_ALLOWED_PROJECT_STATUS;
}

/** Decide whether the issue's own status permits a harness claim. */
export function isIssueStatusEligibleForHarnessCheckout(
  issueStatus: string | null | undefined,
): boolean {
  return typeof issueStatus === "string" && issueStatus.trim() !== "backlog";
}

/**
 * Resolve the whole gate for one wake.
 *
 * Returns `null` when the harness may claim the issue, or the reason it may
 * not. The reason is written to the activity log so an operator can see why a
 * wake did not start work.
 */
export function resolveHarnessCheckoutBlock(input: {
  issueStatus: string | null | undefined;
  hasProject: boolean;
  projectStatus: string | null | undefined;
}): HarnessCheckoutBlockReason | null {
  if (!isIssueStatusEligibleForHarnessCheckout(input.issueStatus)) {
    return "issue_status_backlog";
  }
  if (
    !isProjectStatusEligibleForHarnessCheckout(
      input.projectStatus,
      input.hasProject,
    )
  ) {
    return "project_status_not_in_progress";
  }
  return null;
}

/** Human-readable text for the activity-log record and the run log. */
export function describeHarnessCheckoutBlock(
  reason: HarnessCheckoutBlockReason,
): string {
  if (reason === "issue_status_backlog") {
    return "The harness did not claim the issue because the issue status is backlog.";
  }
  return "The harness did not claim the issue because the project status is not in_progress.";
}

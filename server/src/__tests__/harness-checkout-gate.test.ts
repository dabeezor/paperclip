import { describe, expect, it } from "vitest";
import { PROJECT_STATUSES } from "@paperclipai/shared";
import {
  HARNESS_AUTO_CHECKOUT_ISSUE_STATUSES,
  describeHarnessCheckoutBlock,
  isIssueStatusEligibleForHarnessCheckout,
  isProjectStatusEligibleForHarnessCheckout,
  resolveHarnessCheckoutBlock,
} from "../services/harness-checkout-gate.ts";

describe("isProjectStatusEligibleForHarnessCheckout", () => {
  it("allows an issue whose project is in_progress", () => {
    expect(isProjectStatusEligibleForHarnessCheckout("in_progress", true)).toBe(true);
  });

  it("blocks every project status other than in_progress", () => {
    const parked = PROJECT_STATUSES.filter((status) => status !== "in_progress");
    expect(parked).toEqual(["backlog", "planned", "completed", "cancelled"]);
    for (const status of parked) {
      expect(isProjectStatusEligibleForHarnessCheckout(status, true)).toBe(false);
    }
  });

  it("allows an issue that belongs to no project", () => {
    expect(isProjectStatusEligibleForHarnessCheckout(null, false)).toBe(true);
    expect(isProjectStatusEligibleForHarnessCheckout(undefined, false)).toBe(true);
  });

  it("fails closed when the issue has a project but the status did not load", () => {
    // This is the list-endpoint trap: `GET /api/companies/{id}/issues` does not
    // populate the project, so a caller reading project status from a list
    // response sees an empty field. An empty field must not pass the gate.
    expect(isProjectStatusEligibleForHarnessCheckout(null, true)).toBe(false);
    expect(isProjectStatusEligibleForHarnessCheckout(undefined, true)).toBe(false);
    expect(isProjectStatusEligibleForHarnessCheckout("", true)).toBe(false);
  });
});

describe("isIssueStatusEligibleForHarnessCheckout", () => {
  it("blocks an issue whose own status is backlog", () => {
    expect(isIssueStatusEligibleForHarnessCheckout("backlog")).toBe(false);
  });

  it("allows the scheduled statuses the harness may claim", () => {
    for (const status of HARNESS_AUTO_CHECKOUT_ISSUE_STATUSES) {
      expect(isIssueStatusEligibleForHarnessCheckout(status)).toBe(true);
    }
    expect(HARNESS_AUTO_CHECKOUT_ISSUE_STATUSES).not.toContain("backlog");
  });
});

describe("resolveHarnessCheckoutBlock", () => {
  it("returns no block for a todo issue in an in_progress project", () => {
    expect(
      resolveHarnessCheckoutBlock({
        issueStatus: "todo",
        hasProject: true,
        projectStatus: "in_progress",
      }),
    ).toBeNull();
  });

  it("blocks the ATC-110 case: a backlog issue in a backlog project", () => {
    expect(
      resolveHarnessCheckoutBlock({
        issueStatus: "backlog",
        hasProject: true,
        projectStatus: "backlog",
      }),
    ).toBe("issue_status_backlog");
  });

  it("blocks a todo issue whose project is backlog", () => {
    expect(
      resolveHarnessCheckoutBlock({
        issueStatus: "todo",
        hasProject: true,
        projectStatus: "backlog",
      }),
    ).toBe("project_status_not_in_progress");
  });

  it("blocks a blocked issue whose project is cancelled", () => {
    expect(
      resolveHarnessCheckoutBlock({
        issueStatus: "blocked",
        hasProject: true,
        projectStatus: "cancelled",
      }),
    ).toBe("project_status_not_in_progress");
  });

  it("does not block an issue with no project", () => {
    expect(
      resolveHarnessCheckoutBlock({
        issueStatus: "todo",
        hasProject: false,
        projectStatus: null,
      }),
    ).toBeNull();
  });
});

describe("describeHarnessCheckoutBlock", () => {
  it("names the project status when the project is parked", () => {
    expect(describeHarnessCheckoutBlock("project_status_not_in_progress")).toContain(
      "project status is not in_progress",
    );
  });

  it("names the issue status when the issue is in backlog", () => {
    expect(describeHarnessCheckoutBlock("issue_status_backlog")).toContain(
      "issue status is backlog",
    );
  });
});

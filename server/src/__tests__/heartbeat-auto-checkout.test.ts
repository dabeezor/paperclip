import { describe, expect, it } from "vitest";
import { shouldAutoCheckoutIssueForWake } from "../services/heartbeat.ts";

describe("shouldAutoCheckoutIssueForWake", () => {
  it("auto-checks out an assigned todo issue for an actionable wake", () => {
    expect(shouldAutoCheckoutIssueForWake({
      contextSnapshot: { wakeReason: "issue_assigned" },
      issueStatus: "todo",
      issueAssigneeAgentId: "agent-1",
      isDependencyReady: true,
      agentId: "agent-1",
    })).toBe(true);
  });

  it("auto-checks out a todo issue whose project is in_progress", () => {
    expect(shouldAutoCheckoutIssueForWake({
      contextSnapshot: { wakeReason: "issue_assigned" },
      issueStatus: "todo",
      issueAssigneeAgentId: "agent-1",
      isDependencyReady: true,
      agentId: "agent-1",
      issueHasProject: true,
      issueProjectStatus: "in_progress",
    })).toBe(true);
  });

  it("does not auto-checkout an issue whose own status is backlog", () => {
    expect(shouldAutoCheckoutIssueForWake({
      contextSnapshot: { wakeReason: "issue_assigned" },
      issueStatus: "backlog",
      issueAssigneeAgentId: "agent-1",
      isDependencyReady: true,
      agentId: "agent-1",
      issueHasProject: true,
      issueProjectStatus: "in_progress",
    })).toBe(false);
  });

  it("does not auto-checkout an issue whose project status is not in_progress", () => {
    for (const projectStatus of ["backlog", "planned", "completed", "cancelled"]) {
      expect(shouldAutoCheckoutIssueForWake({
        contextSnapshot: { wakeReason: "issue_assigned" },
        issueStatus: "todo",
        issueAssigneeAgentId: "agent-1",
        isDependencyReady: true,
        agentId: "agent-1",
        issueHasProject: true,
        issueProjectStatus: projectStatus,
      })).toBe(false);
    }
  });

  it("does not auto-checkout an in_progress issue whose project is parked", () => {
    expect(shouldAutoCheckoutIssueForWake({
      contextSnapshot: { wakeReason: "issue_status_changed" },
      issueStatus: "in_progress",
      issueAssigneeAgentId: "agent-1",
      isDependencyReady: true,
      agentId: "agent-1",
      issueHasProject: true,
      issueProjectStatus: "backlog",
    })).toBe(false);
  });

  it("still auto-checks out an issue that belongs to no project", () => {
    expect(shouldAutoCheckoutIssueForWake({
      contextSnapshot: { wakeReason: "issue_assigned" },
      issueStatus: "todo",
      issueAssigneeAgentId: "agent-1",
      isDependencyReady: true,
      agentId: "agent-1",
      issueHasProject: false,
      issueProjectStatus: null,
    })).toBe(true);
  });

  it("does not auto-checkout pending execution-review state even if the row status is todo", () => {
    const reviewerAgentId = "11111111-1111-4111-8111-111111111111";
    const coderAgentId = "22222222-2222-4222-8222-222222222222";
    expect(shouldAutoCheckoutIssueForWake({
      contextSnapshot: { wakeReason: "issue_recovery_action_restored" },
      issueStatus: "todo",
      issueAssigneeAgentId: reviewerAgentId,
      issueExecutionState: {
        status: "pending",
        currentStageId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        currentStageIndex: 0,
        currentStageType: "review",
        currentParticipant: { type: "agent", agentId: reviewerAgentId },
        returnAssignee: { type: "agent", agentId: coderAgentId },
        reviewRequest: null,
        completedStageIds: [],
        lastDecisionId: null,
        lastDecisionOutcome: null,
      },
      isDependencyReady: true,
      agentId: reviewerAgentId,
    })).toBe(false);
  });
});

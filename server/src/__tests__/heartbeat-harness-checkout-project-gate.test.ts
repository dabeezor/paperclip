import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  activityLog,
  agents,
  companies,
  createDb,
  issues,
  projects,
} from "@paperclipai/db";
import { runningProcesses } from "../adapters/index.js";
import { heartbeatService } from "../services/heartbeat.ts";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.ts";
import { createControlledGatewayServer } from "./helpers/controlled-gateway-server.ts";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

if (!embeddedPostgresSupport.supported) {
  console.warn(
    `Skipping embedded Postgres harness checkout gate tests on this host: ${embeddedPostgresSupport.reason ?? "unsupported environment"}`,
  );
}

async function waitFor(
  condition: () => boolean | Promise<boolean>,
  timeoutMs = 10_000,
  intervalMs = 50,
) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await condition()) return;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error("Timed out waiting for condition");
}

async function closeDbClient(db: ReturnType<typeof createDb> | undefined) {
  await db?.$client?.end?.({ timeout: 0 });
}

describeEmbeddedPostgres("run harness checkout project-status gate", () => {
  let db!: ReturnType<typeof createDb>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;

  beforeAll(async () => {
    const started = await startEmbeddedPostgresTestDatabase("paperclip-harness-checkout-gate-");
    db = createDb(started.connectionString);
    tempDb = started;
  }, 120_000);

  afterAll(async () => {
    await heartbeatService(db).drainActiveRunExecutions();
    await closeDbClient(db);
    await tempDb?.cleanup();
  });

  afterEach(() => {
    runningProcesses.clear();
  });

  /**
   * Build one company, one project, one gateway-backed agent, and one issue
   * assigned to that agent. Then wake the agent on that issue and wait until
   * the harness has finished its checkout decision.
   */
  async function wakeAgentOnIssue(input: {
    projectStatus: string | null;
    issueStatus: string;
    title: string;
  }) {
    const gateway = await createControlledGatewayServer();
    const companyId = randomUUID();
    const agentId = randomUUID();
    const issueId = randomUUID();
    const projectId = input.projectStatus === null ? null : randomUUID();
    const issuePrefix = `T${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`;
    const heartbeat = heartbeatService(db);

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix,
      requireBoardApprovalForNewAgents: false,
      defaultResponsibleUserId: "responsible-user",
    });

    if (projectId && input.projectStatus) {
      await db.insert(projects).values({
        id: projectId,
        companyId,
        name: "Gated project",
        status: input.projectStatus,
      });
    }

    await db.insert(agents).values({
      id: agentId,
      companyId,
      name: "Gateway Agent",
      role: "engineer",
      status: "idle",
      adapterType: "openclaw_gateway",
      adapterConfig: {
        url: gateway.url,
        headers: { "x-openclaw-token": "gateway-token" },
        payloadTemplate: { message: "wake now" },
        waitTimeoutMs: 2_000,
      },
      runtimeConfig: {},
      permissions: {},
    });

    await db.insert(issues).values({
      id: issueId,
      companyId,
      projectId,
      title: input.title,
      status: input.issueStatus,
      priority: "medium",
      responsibleUserId: "responsible-user",
      assigneeAgentId: agentId,
      issueNumber: 1,
      identifier: `${issuePrefix}-1`,
    });

    const run = await heartbeat.wakeup(agentId, {
      source: "assignment",
      triggerDetail: "system",
      reason: "issue_assigned",
      payload: { issueId },
      contextSnapshot: { issueId, taskId: issueId, wakeReason: "issue_assigned" },
      requestedByActorType: "system",
      requestedByActorId: null,
    });

    expect(run).not.toBeNull();
    // The gateway holds the first `agent.wait` open, so the run is still live
    // once its payload lands. Every checkout decision is already made by then.
    await waitFor(() => gateway.getAgentPayloads().length === 1);

    const issueRow = await db
      .select({
        status: issues.status,
        checkoutRunId: issues.checkoutRunId,
        executionRunId: issues.executionRunId,
      })
      .from(issues)
      .where(eq(issues.id, issueId))
      .then((rows) => rows[0] ?? null);

    const activity = await db
      .select({ action: activityLog.action, details: activityLog.details })
      .from(activityLog)
      .where(
        and(eq(activityLog.entityType, "issue"), eq(activityLog.entityId, issueId)),
      );

    const message = String(gateway.getAgentPayloads()[0]?.message ?? "");

    gateway.releaseFirstWait();
    await gateway.close();

    return { runId: run?.id ?? null, issueRow, activity, message };
  }

  it("does not claim a todo issue whose project status is backlog", async () => {
    const result = await wakeAgentOnIssue({
      projectStatus: "backlog",
      issueStatus: "todo",
      title: "Parked project work",
    });

    // The gate governs the claim: the issue keeps its own status and no run
    // holds a checkout on it. `executionRunId` is the separate run-dispatch
    // lock that binds a live run to an issue, and it is released when the run
    // ends; the gate deliberately does not touch it.
    expect(result.issueRow).toMatchObject({
      status: "todo",
      checkoutRunId: null,
    });
    expect(result.message).not.toContain("already claimed by the harness");
    expect(result.activity.map((row) => row.action)).toContain(
      "issue.harness_checkout_skipped",
    );
    const skipped = result.activity.find(
      (row) => row.action === "issue.harness_checkout_skipped",
    );
    expect(skipped?.details).toMatchObject({
      reason: "project_status_not_in_progress",
      projectStatus: "backlog",
      actor: "run_harness",
    });
    expect(result.activity.map((row) => row.action)).not.toContain("issue.checked_out");
  }, 120_000);

  it("does not claim an issue whose own status is backlog", async () => {
    const result = await wakeAgentOnIssue({
      projectStatus: "in_progress",
      issueStatus: "backlog",
      title: "Unscheduled work",
    });

    expect(result.issueRow).toMatchObject({
      status: "backlog",
      checkoutRunId: null,
    });
    expect(result.message).not.toContain("already claimed by the harness");
    const skipped = result.activity.find(
      (row) => row.action === "issue.harness_checkout_skipped",
    );
    expect(skipped?.details).toMatchObject({
      reason: "issue_status_backlog",
      issueStatus: "backlog",
      actor: "run_harness",
    });
  }, 120_000);

  it("claims a todo issue whose project status is in_progress and records the transition", async () => {
    const result = await wakeAgentOnIssue({
      projectStatus: "in_progress",
      issueStatus: "todo",
      title: "Active project work",
    });

    expect(result.issueRow).toMatchObject({
      status: "in_progress",
      checkoutRunId: result.runId,
      executionRunId: result.runId,
    });
    expect(result.message).toContain("- checkout: already claimed by the harness for this run");

    // Acceptance criterion 3: the harness transition is visible in the activity
    // log, which is what `GET /api/issues/{id}/activity` reads.
    const checkedOut = result.activity.find((row) => row.action === "issue.checked_out");
    expect(checkedOut).toBeDefined();
    expect(checkedOut?.details).toMatchObject({
      source: "harness_auto_checkout",
      fromStatus: "todo",
      toStatus: "in_progress",
      projectStatus: "in_progress",
      actor: "run_harness",
    });
  }, 120_000);

  it("still claims an issue that belongs to no project", async () => {
    const result = await wakeAgentOnIssue({
      projectStatus: null,
      issueStatus: "todo",
      title: "Unprojected work",
    });

    expect(result.issueRow).toMatchObject({
      status: "in_progress",
      checkoutRunId: result.runId,
    });
    expect(result.activity.map((row) => row.action)).toContain("issue.checked_out");
  }, 120_000);
});

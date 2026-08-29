import { createHash } from "node:crypto";
import type { ChildProcess } from "node:child_process";
import { once } from "node:events";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  realpath,
  rename,
  rm,
  symlink,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveQualifiedAcpxProfile } from "./qualified-profiles.js";
import {
  guardSnapshotModuleLookup,
  verifiedExecutableOpenFlags,
  verifyQualifiedAcpxInstallation,
} from "./installation-integrity.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("ACPX installation integrity", () => {
  it("does not delegate non-Linux snapshot filesystem lookups", () => {
    for (const platform of ["darwin", "freebsd", "win32"] as const) {
      const nextResolve = vi.fn(() => ({ url: "file:///attacker.js" }));
      const nextLoad = vi.fn(() => ({ source: "attacker" }));
      expect(() =>
        guardSnapshotModuleLookup(platform, true, nextResolve),
      ).toThrow("requires Linux descriptor-pinned paths");
      expect(() => guardSnapshotModuleLookup(platform, true, nextLoad)).toThrow(
        "requires Linux descriptor-pinned paths",
      );
      expect(nextResolve).not.toHaveBeenCalled();
      expect(nextLoad).not.toHaveBeenCalled();
    }

    const pinnedLookup = vi.fn(() => "verified");
    expect(guardSnapshotModuleLookup("linux", true, pinnedLookup)).toBe(
      "verified",
    );
    expect(pinnedLookup).toHaveBeenCalledOnce();

    const builtinLookup = vi.fn(() => "builtin");
    expect(guardSnapshotModuleLookup("darwin", false, builtinLookup)).toBe(
      "builtin",
    );
    expect(builtinLookup).toHaveBeenCalledOnce();
  });

  it("fails closed when the platform cannot atomically open without following symlinks", () => {
    expect(() => verifiedExecutableOpenFlags("win32", 0x20000)).toThrow(
      "requires atomic no-follow",
    );
    expect(() => verifiedExecutableOpenFlags("linux", undefined)).toThrow(
      "requires atomic no-follow",
    );
    expect(verifiedExecutableOpenFlags("linux", 0x20000)).not.toBe(0);
  });

  it("accepts the exact package, version, executable, and runtime", async () => {
    const fixture = await installationFixture();
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    expect(installation).toMatchObject({
      commandDigest: fixture.profile.commandDigest,
      openCommand: expect.any(Function),
      agentServerPackageJsonPath: await realpath(fixture.serverPackageJsonPath),
      agentRuntimePackageJsonPath: await realpath(
        fixture.runtimePackageJsonPath,
      ),
    });
  });

  it("rejects package version and executable digest drift", async () => {
    const fixture = await installationFixture();
    await writeFile(
      fixture.serverPackageJsonPath,
      JSON.stringify({ version: "0.0.34", bin: "bin/server.js" }),
    );
    await expect(
      verifyQualifiedAcpxInstallation(fixture.profile, fixture.resolve),
    ).rejects.toThrow(/package version mismatch/);

    await writeFile(
      fixture.serverPackageJsonPath,
      JSON.stringify({ version: "0.0.33", bin: "bin/server.js" }),
    );
    await writeFile(fixture.commandPath, "changed executable");
    await expect(
      verifyQualifiedAcpxInstallation(fixture.profile, fixture.resolve),
    ).rejects.toThrow(/digest mismatch/);
  });

  it("rejects ambiguous and escaping executable metadata", async () => {
    const fixture = await installationFixture();
    await writeFile(
      fixture.serverPackageJsonPath,
      JSON.stringify({
        version: "0.0.33",
        bin: { first: "bin/server.js", second: "bin/other.js" },
      }),
    );
    await expect(
      verifyQualifiedAcpxInstallation(fixture.profile, fixture.resolve),
    ).rejects.toThrow(/one relative executable/);

    await writeFile(
      fixture.serverPackageJsonPath,
      JSON.stringify({ version: "0.0.33", bin: "../outside.js" }),
    );
    await expect(
      verifyQualifiedAcpxInstallation(fixture.profile, fixture.resolve),
    ).rejects.toThrow(/escapes its package/);
  });

  it("rejects runtime version drift", async () => {
    const fixture = await installationFixture();
    await writeFile(
      fixture.runtimePackageJsonPath,
      JSON.stringify({ version: "0.84.3" }),
    );
    await expect(
      verifyQualifiedAcpxInstallation(fixture.profile, fixture.resolve),
    ).rejects.toThrow(/runtime version mismatch/);
  });

  it("rejects an executable symlink even when its target has the expected digest", async () => {
    const fixture = await installationFixture();
    const target = join(fixture.root, "outside.js");
    await writeFile(target, fixture.command);
    await rm(fixture.commandPath);
    await symlink(target, fixture.commandPath);

    await expect(
      verifyQualifiedAcpxInstallation(fixture.profile, fixture.resolve),
    ).rejects.toThrow(/real regular file|no-follow regular file/);
  });

  it("detects pathname replacement before opening a launch lease", async () => {
    const fixture = await installationFixture();
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    await writeFile(fixture.commandPath, "replacement");

    await expect(installation.openCommand()).rejects.toThrow(
      /digest mismatch|identity changed/,
    );
  });

  it("rejects a hard-linked executable through a replacement directory", async () => {
    const fixture = await installationFixture();
    const attackerDirectory = join(fixture.root, "attacker-bin");
    await mkdir(attackerDirectory);
    await link(fixture.commandPath, join(attackerDirectory, "server.js"));
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    await rename(
      fixture.commandDirectory,
      `${fixture.commandDirectory}.verified`,
    );
    await symlink(attackerDirectory, fixture.commandDirectory);

    await expect(installation.openCommand()).rejects.toThrow(
      /executable directory (must be a real directory|identity changed)/,
    );
  });

  it("launches the verified bytes after its pathname is replaced", async () => {
    const fixture = await installationFixture();
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    const lease = await installation.openCommand();
    const replacement = `${fixture.commandPath}.replacement`;
    await writeFile(
      replacement,
      '#!/usr/bin/env node\nprocess.stdout.write("replacement");\n',
    );
    await chmod(replacement, 0o755);
    await rename(replacement, fixture.commandPath);

    await expectOutput(lease.spawn(), "verified");
  });

  it("launches the lexical verified snapshot after symlink replacement", async () => {
    const fixture = await installationFixture();
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    const lease = await installation.openCommand();
    const outside = join(fixture.root, "outside.js");
    await writeFile(
      outside,
      '#!/usr/bin/env node\nprocess.stdout.write("symlink-target");\n',
    );
    await rm(fixture.commandPath);
    await symlink(outside, fixture.commandPath);

    await expectOutput(lease.spawn(), "verified");
  });

  it("launches the verified bytes after the open inode is modified", async () => {
    const fixture = await installationFixture();
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    const lease = await installation.openCommand();
    const before = await stat(fixture.commandPath, { bigint: true });
    await writeFile(
      fixture.commandPath,
      '#!/usr/bin/env node\nprocess.stdout.write("modified");\n',
    );
    const after = await stat(fixture.commandPath, { bigint: true });
    expect(after.ino).toBe(before.ino);

    await expectOutput(lease.spawn(), "verified");
  });

  it("drops inherited and caller-supplied Node preload options", async () => {
    const fixture = await installationFixture();
    const installation = await verifyQualifiedAcpxInstallation(
      fixture.profile,
      fixture.resolve,
    );
    const preload = join(fixture.root, "unverified-preload.cjs");
    await writeFile(preload, 'process.stdout.write("unverified-preload");\n');
    const previousNodeOptions = process.env.NODE_OPTIONS;
    let inheritedChild: ChildProcess;
    try {
      process.env.NODE_OPTIONS = `--require=${preload}`;
      inheritedChild = (await installation.openCommand()).spawn();
    } finally {
      if (previousNodeOptions === undefined) delete process.env.NODE_OPTIONS;
      else process.env.NODE_OPTIONS = previousNodeOptions;
    }
    await expectOutput(inheritedChild, "verified");

    await expectOutput(
      (await installation.openCommand()).spawn([], {
        env: { ...process.env, node_options: `--require=${preload}` },
      }),
      "verified",
    );
  });

  it("loads a verified ESM snapshot with relative imports and arguments", async () => {
    const fixture = await installationFixture();
    const command = [
      'import { fileURLToPath } from "node:url";',
      'import value from "./value.js";',
      "process.stdout.write(JSON.stringify({ value, argument: process.argv[2], argv: process.argv[1], filename: fileURLToPath(import.meta.url) }));",
    ].join("\n");
    await Promise.all([
      writeFile(
        fixture.serverPackageJsonPath,
        JSON.stringify({
          version: "0.0.33",
          type: "module",
          bin: "bin/server.js",
        }),
      ),
      writeFile(fixture.commandPath, command),
      writeFile(
        join(fixture.commandDirectory, "value.js"),
        'export default "relative";',
      ),
    ]);
    const installation = await verifyQualifiedAcpxInstallation(
      {
        ...fixture.profile,
        commandDigest: `sha256:${createHash("sha256").update(command).digest("hex")}`,
      },
      fixture.resolve,
    );

    const child = (await installation.openCommand()).spawn(["argument"]);
    if (process.platform === "linux") {
      await expectOutput(
        child,
        JSON.stringify({
          value: "relative",
          argument: "argument",
          argv: fixture.commandPath,
          filename: fixture.commandPath,
        }),
      );
    } else {
      await expectFailure(child, "requires Linux descriptor-pinned paths");
    }
  });

  it("pins relative imports when the command directory is replaced", async () => {
    const fixture = await installationFixture();
    const command = [
      'import { fileURLToPath } from "node:url";',
      'import value from "./value.js";',
      "process.stdout.write(JSON.stringify({ value, argv: process.argv[1], filename: fileURLToPath(import.meta.url) }));",
    ].join("\n");
    const attackerDirectory = join(fixture.root, "attacker-bin");
    await mkdir(attackerDirectory);
    await Promise.all([
      writeFile(
        fixture.serverPackageJsonPath,
        JSON.stringify({
          version: "0.0.33",
          type: "module",
          bin: "bin/server.js",
        }),
      ),
      writeFile(fixture.commandPath, command),
      writeFile(
        join(fixture.commandDirectory, "value.js"),
        'export default "verified-relative";',
      ),
      writeFile(
        join(attackerDirectory, "value.js"),
        'export default "attacker-relative";',
      ),
    ]);
    await link(fixture.commandPath, join(attackerDirectory, "server.js"));
    const installation = await verifyQualifiedAcpxInstallation(
      {
        ...fixture.profile,
        commandDigest: `sha256:${createHash("sha256").update(command).digest("hex")}`,
      },
      fixture.resolve,
    );
    const lease = await installation.openCommand();
    const verifiedDirectory = `${fixture.commandDirectory}.verified`;
    await rename(fixture.commandDirectory, verifiedDirectory);
    await symlink(attackerDirectory, fixture.commandDirectory);
    const verifiedCommand = await stat(join(verifiedDirectory, "server.js"), {
      bigint: true,
    });
    const redirectedCommand = await stat(fixture.commandPath, { bigint: true });
    expect(redirectedCommand.dev).toBe(verifiedCommand.dev);
    expect(redirectedCommand.ino).toBe(verifiedCommand.ino);

    if (process.platform === "linux") {
      await expectOutput(
        lease.spawn(),
        JSON.stringify({
          value: "verified-relative",
          argv: fixture.commandPath,
          filename: fixture.commandPath,
        }),
      );
    } else {
      await expectFailure(
        lease.spawn(),
        "requires Linux descriptor-pinned paths",
      );
    }
  });

  it("keeps canonical CommonJS identity while pinning relative requires", async () => {
    const fixture = await installationFixture();
    const command = [
      'const value = require("./value");',
      "process.stdout.write(JSON.stringify({ value, argument: process.argv[2], argv: process.argv[1], filename: __filename, directory: __dirname }));",
    ].join("\n");
    const attackerDirectory = join(fixture.root, "attacker-bin");
    await mkdir(attackerDirectory);
    await Promise.all([
      writeFile(fixture.commandPath, command),
      writeFile(
        join(fixture.commandDirectory, "value.js"),
        'module.exports = "verified-relative";',
      ),
      writeFile(
        join(attackerDirectory, "value.js"),
        'module.exports = "attacker-relative";',
      ),
    ]);
    await link(fixture.commandPath, join(attackerDirectory, "server.js"));
    const installation = await verifyQualifiedAcpxInstallation(
      {
        ...fixture.profile,
        commandDigest: `sha256:${createHash("sha256").update(command).digest("hex")}`,
      },
      fixture.resolve,
    );
    const lease = await installation.openCommand();
    await rename(
      fixture.commandDirectory,
      `${fixture.commandDirectory}.verified`,
    );
    await symlink(attackerDirectory, fixture.commandDirectory);

    const child = lease.spawn(["argument"]);
    if (process.platform === "linux") {
      await expectOutput(
        child,
        JSON.stringify({
          value: "verified-relative",
          argument: "argument",
          argv: fixture.commandPath,
          filename: fixture.commandPath,
          directory: dirname(fixture.commandPath),
        }),
      );
    } else {
      await expectFailure(child, "requires Linux descriptor-pinned paths");
    }
  });

  it("pins a bare entry require when the command directory is replaced", async () => {
    const fixture = await installationFixture();
    const command = [
      'const value = require("verified-dependency");',
      "process.stdout.write(value);",
    ].join("\n");
    const attackerDirectory = join(fixture.root, "attacker-bin");
    const verifiedDependency = join(
      fixture.commandDirectory,
      "node_modules",
      "verified-dependency",
    );
    const attackerDependency = join(
      attackerDirectory,
      "node_modules",
      "verified-dependency",
    );
    await Promise.all([
      mkdir(verifiedDependency, { recursive: true }),
      mkdir(attackerDependency, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(fixture.commandPath, command),
      writeFile(
        join(verifiedDependency, "package.json"),
        JSON.stringify({ name: "verified-dependency", main: "index.js" }),
      ),
      writeFile(
        join(verifiedDependency, "index.js"),
        'module.exports = "verified-bare";',
      ),
      writeFile(
        join(attackerDependency, "package.json"),
        JSON.stringify({ name: "verified-dependency", main: "index.js" }),
      ),
      writeFile(
        join(attackerDependency, "index.js"),
        'module.exports = "attacker-bare";',
      ),
    ]);
    await link(fixture.commandPath, join(attackerDirectory, "server.js"));
    const installation = await verifyQualifiedAcpxInstallation(
      {
        ...fixture.profile,
        commandDigest: `sha256:${createHash("sha256").update(command).digest("hex")}`,
      },
      fixture.resolve,
    );
    const lease = await installation.openCommand();
    await rename(
      fixture.commandDirectory,
      `${fixture.commandDirectory}.verified`,
    );
    await symlink(attackerDirectory, fixture.commandDirectory);

    const child = lease.spawn();
    if (process.platform === "linux") {
      await expectOutput(child, "verified-bare");
    } else {
      await expectFailure(child, "requires Linux descriptor-pinned paths");
    }
  });
});

async function expectOutput(
  child: ChildProcess,
  expected: string,
): Promise<void> {
  let stdout = "";
  let stderr = "";
  child.stdout?.setEncoding("utf8");
  child.stdout?.on("data", (chunk) => {
    stdout += String(chunk);
  });
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk) => {
    stderr += String(chunk);
  });
  const [exitCode] = await once(child, "exit");
  expect(exitCode, stderr).toBe(0);
  expect(stdout).toBe(expected);
}

async function expectFailure(
  child: ChildProcess,
  expected: string,
): Promise<void> {
  let stderr = "";
  child.stderr?.setEncoding("utf8");
  child.stderr?.on("data", (chunk) => {
    stderr += String(chunk);
  });
  const [exitCode] = await once(child, "exit");
  expect(exitCode).not.toBe(0);
  expect(stderr).toContain(expected);
}

async function installationFixture() {
  const root = await mkdtemp(join(tmpdir(), "paperclip-acpx-installation-"));
  temporaryDirectories.push(root);
  const serverDirectory = join(root, "pi-acp");
  const runtimeDirectory = join(root, "pi-runtime");
  const commandDirectory = join(serverDirectory, "bin");
  await Promise.all([
    mkdir(commandDirectory, { recursive: true }),
    mkdir(runtimeDirectory, { recursive: true }),
  ]);
  const serverPackageJsonPath = join(serverDirectory, "package.json");
  const runtimePackageJsonPath = join(runtimeDirectory, "package.json");
  const commandPath = join(commandDirectory, "server.js");
  const command = '#!/usr/bin/env node\nprocess.stdout.write("verified");\n';
  await Promise.all([
    writeFile(
      serverPackageJsonPath,
      JSON.stringify({ version: "0.0.33", bin: "bin/server.js" }),
    ),
    writeFile(runtimePackageJsonPath, JSON.stringify({ version: "0.84.2" })),
    writeFile(commandPath, command),
  ]);
  await chmod(commandPath, 0o755);
  const base = resolveQualifiedAcpxProfile(
    "pi",
    "openrouter/deepseek/deepseek-v4-flash-0731",
  );
  const profile = {
    ...base,
    commandDigest: `sha256:${createHash("sha256").update(command).digest("hex")}`,
  };
  const paths = new Map([
    ["pi-acp", serverPackageJsonPath],
    ["@earendil-works/pi-coding-agent", runtimePackageJsonPath],
  ]);
  return {
    root,
    command,
    profile,
    commandPath,
    commandDirectory,
    serverPackageJsonPath,
    runtimePackageJsonPath,
    resolve(packageName: string): string {
      const resolved = paths.get(packageName);
      if (!resolved) throw new Error(`unexpected package ${packageName}`);
      return resolved;
    },
  };
}

import { createHash } from "node:crypto";
import {
  spawn as spawnChildProcess,
  type ChildProcess,
  type SpawnOptionsWithoutStdio,
} from "node:child_process";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readFile,
  realpath,
  stat,
  type FileHandle,
} from "node:fs/promises";
import { createRequire } from "node:module";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  relative,
  resolve,
} from "node:path";
import type { Readable, Writable } from "node:stream";

import type { QualifiedAcpxProfile } from "./qualified-profiles.js";

const MAX_PACKAGE_JSON_BYTES = 256 * 1024;
const MAX_AGENT_COMMAND_BYTES = 16 * 1024 * 1024;
const COMMAND_SOURCE_FD = 3;
const COMMAND_DIRECTORY_FD = 4;
const DEPENDENCY_ANCESTOR_FD_START = 5;
const MAX_DEPENDENCY_ANCESTORS = 64;
const PROVIDER_GUARDIAN_HANDSHAKE_TIMEOUT_MS = 1_000;

export const PROVIDER_LIFETIME_GUARDIAN_SOURCE = `
const fs = require("node:fs");
const { spawn } = require("node:child_process");
const dependencyAncestorCount = Number.parseInt(process.argv[4], 10);
if (!Number.isSafeInteger(dependencyAncestorCount) || dependencyAncestorCount < 1 || dependencyAncestorCount > ${MAX_DEPENDENCY_ANCESTORS}) throw new Error("ACPX provider dependency ancestry is invalid");
const OWNER_FD = ${DEPENDENCY_ANCESTOR_FD_START} + dependencyAncestorCount;
const OWNERSHIP_FD = OWNER_FD + 1;
const CREDENTIAL_FENCE_FD = OWNERSHIP_FD + 1;
const dependencyAncestorFds = Array.from({ length: dependencyAncestorCount }, (_, index) => ${DEPENDENCY_ANCESTOR_FD_START} + index);
let provider;
let reaped = false;
let shutdownStarted = false;
const reap = () => {
  if (reaped) return;
  reaped = true;
  // This sentinel is the provider group's leader. It remains alive until this
  // one atomic signal, pinning the numeric group identity against PID reuse.
  process.kill(-process.pid, "SIGKILL");
};
const owner = fs.createReadStream("", { fd: OWNER_FD, autoClose: false });
owner.once("end", reap);
owner.once("error", reap);
owner.resume();
// Fail before provider code exists unless the inherited kernel fence is live.
fs.fstatSync(CREDENTIAL_FENCE_FD);
const shutdown = () => {
  if (shutdownStarted || reaped) return;
  shutdownStarted = true;
  try {
    provider?.kill("SIGTERM");
  } catch {
    reap();
    return;
  }
  setTimeout(reap, 1_000);
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("SIGHUP", shutdown);
try {
  provider = spawn(
    process.execPath,
    ["--eval", process.argv[1], ...process.argv.slice(2)],
    {
      cwd: process.cwd(),
      detached: false,
      env: process.env,
      shell: false,
      stdio: [0, 1, 2, ${COMMAND_SOURCE_FD}, ${COMMAND_DIRECTORY_FD}, ...dependencyAncestorFds],
      windowsHide: true,
    },
  );
  provider.once("error", reap);
  provider.once("exit", reap);
  provider.once("spawn", () => {
    try {
      fs.writeSync(OWNERSHIP_FD, "owned\\n");
    } catch {
      reap();
    }
  });
} catch {
  reap();
}
`;

const providerGuardianOwnership = new WeakMap<ChildProcess, Promise<void>>();

export type AcpxPackageJsonResolver = (packageName: string) => string;

export interface VerifiedAcpxInstallation {
  readonly commandDigest: string;
  readonly agentServerPackageJsonPath: string;
  readonly agentRuntimePackageJsonPath: string | null;
  openCommand(): Promise<VerifiedAcpxCommandLease>;
}

export interface VerifiedAcpxCommandLease {
  spawn(
    args?: readonly string[],
    options?: SpawnOptionsWithoutStdio,
    lifetime?: VerifiedAcpxProviderLifetime,
  ): ChildProcess;
  close(): Promise<void>;
}

export interface VerifiedAcpxProviderLifetime {
  /** Listening socket that fences the canonical Codex credential home. */
  credentialFenceFd: number;
  /** Persist the guardian PID before provider admission can succeed. */
  activateCredentialFenceOwner(pid: number): Promise<void>;
}

/** Wait until the verified wrapper has armed owner-death and credential fencing. */
export async function awaitVerifiedAcpxProviderOwnership(
  child: ChildProcess,
): Promise<void> {
  await (providerGuardianOwnership.get(child) ?? Promise.resolve());
}

interface VerifiedAcpxCommandIdentity {
  device: string;
  inode: string;
  size: string;
  modifiedNanoseconds: string;
  changedNanoseconds: string;
}

interface VerifiedAcpxDirectoryIdentity {
  device: string;
  inode: string;
}

interface VerifiedAcpxDependencyAncestor {
  path: string;
  identity: VerifiedAcpxDirectoryIdentity;
}

type AcpxCommandFormat = "commonjs" | "module";

const COMMONJS_SNAPSHOT_BOOTSTRAP = snapshotBootstrap("commonjs");
const MODULE_SNAPSHOT_BOOTSTRAP = snapshotBootstrap("module");

/** Resolve and verify every installed artifact bound by a qualified profile. */
export async function verifyQualifiedAcpxInstallation(
  profile: QualifiedAcpxProfile,
  resolvePackageJson: AcpxPackageJsonResolver = defaultPackageJsonResolver,
): Promise<VerifiedAcpxInstallation> {
  const serverPackageJsonPath = await realpath(
    resolvePackageJson(profile.agentServerPackage),
  );
  const serverPackage = await readPackageJson(
    serverPackageJsonPath,
    profile.agentServerPackage,
  );
  if (serverPackage.version !== profile.agentServerVersion) {
    throw new Error(
      `ACPX ${profile.agent} package version mismatch: expected ${profile.agentServerVersion}, received ${serverPackage.version ?? "unknown"}`,
    );
  }
  const relativeCommand = oneExecutable(serverPackage.bin, profile.agent);
  const commandFormat = executableFormat(
    relativeCommand,
    serverPackage.type,
    profile.agent,
  );
  const packageDirectory = dirname(serverPackageJsonPath);
  const unresolvedCommandPath = resolve(packageDirectory, relativeCommand);
  if (!isInside(packageDirectory, unresolvedCommandPath)) {
    throw new Error(`ACPX ${profile.agent} executable escapes its package`);
  }
  const commandDirectory = await realpath(dirname(unresolvedCommandPath));
  if (!isInsideOrEqual(packageDirectory, commandDirectory)) {
    throw new Error(`ACPX ${profile.agent} executable escapes its package`);
  }
  const commandPath = resolve(
    commandDirectory,
    basename(unresolvedCommandPath),
  );
  const verifiedDirectory = await openVerifiedCommandDirectory(
    commandDirectory,
    profile.agent,
  );
  const commandDirectoryIdentity = verifiedDirectory.identity;
  await verifiedDirectory.handle.close();
  const dependencyAncestors = await inspectDependencyAncestors(
    commandDirectory,
    profile.agent,
  );
  const command = await inspectCommand(
    commandPath,
    profile.commandDigest,
    profile.agent,
  );

  let runtimePackageJsonPath: string | null = null;
  if (profile.agentRuntimePackage !== null) {
    if (profile.agentRuntimeVersion === null) {
      throw new Error("Qualified ACPX runtime package omitted its version");
    }
    runtimePackageJsonPath = await realpath(
      resolvePackageJson(profile.agentRuntimePackage),
    );
    const runtimePackage = await readPackageJson(
      runtimePackageJsonPath,
      profile.agentRuntimePackage,
    );
    if (runtimePackage.version !== profile.agentRuntimeVersion) {
      throw new Error(
        `ACPX ${profile.agent} runtime version mismatch: expected ${profile.agentRuntimeVersion}, received ${runtimePackage.version ?? "unknown"}`,
      );
    }
  } else if (profile.agentRuntimeVersion !== null) {
    throw new Error("Qualified ACPX runtime version omitted its package");
  }

  const commandDigest = command.digest;
  const commandIdentity = command.identity;
  return Object.freeze({
    commandDigest,
    agentServerPackageJsonPath: serverPackageJsonPath,
    agentRuntimePackageJsonPath: runtimePackageJsonPath,
    async openCommand(): Promise<VerifiedAcpxCommandLease> {
      const currentDirectory = await openVerifiedCommandDirectory(
        commandDirectory,
        "provider",
      );
      if (
        !sameDirectoryIdentity(
          currentDirectory.identity,
          commandDirectoryIdentity,
        )
      ) {
        await currentDirectory.handle.close();
        throw new Error(
          "ACPX provider executable directory identity changed after verification",
        );
      }
      let currentDependencyAncestors: FileHandle[] = [];
      try {
        currentDependencyAncestors = await openDependencyAncestors(
          dependencyAncestors,
        );
        const current = await inspectCommand(
          commandPath,
          commandDigest,
          "provider",
        );
        if (!sameIdentity(current.identity, commandIdentity)) {
          current.bytes.fill(0);
          throw new Error(
            "ACPX provider executable identity changed after verification",
          );
        }
        return commandLease(
          commandDirectory,
          basename(commandPath),
          commandFormat,
          current.bytes,
          currentDirectory.handle,
          currentDependencyAncestors,
        );
      } catch (error) {
        await Promise.all([
          currentDirectory.handle.close(),
          ...currentDependencyAncestors.map((handle) => handle.close()),
        ]);
        throw error;
      }
    },
  });
}

function defaultPackageJsonResolver(packageName: string): string {
  return createRequire(import.meta.url).resolve(`${packageName}/package.json`);
}

async function readPackageJson(
  packageJsonPath: string,
  packageName: string,
): Promise<{ version?: string; bin?: unknown; type?: unknown }> {
  const bytes = await readBoundedRegularFile(
    packageJsonPath,
    MAX_PACKAGE_JSON_BYTES,
    `${packageName} package.json`,
  );
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`ACPX package ${packageName} has malformed package.json`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`ACPX package ${packageName} has invalid package metadata`);
  }
  return value as { version?: string; bin?: unknown; type?: unknown };
}

async function readBoundedRegularFile(
  filePath: string,
  maxBytes: number,
  label: string,
): Promise<Buffer> {
  const metadata = await stat(filePath);
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > maxBytes) {
    throw new Error(`${label} must be a bounded regular file`);
  }
  const bytes = await readFile(filePath);
  if (bytes.length < 1 || bytes.length > maxBytes) {
    throw new Error(`${label} changed outside its bounded size`);
  }
  return bytes;
}

async function inspectCommand(
  commandPath: string,
  expectedDigest: string,
  agent: string,
): Promise<{
  bytes: Buffer;
  digest: string;
  identity: VerifiedAcpxCommandIdentity;
}> {
  const lexicalBefore = await lstat(commandPath, { bigint: true }).catch(
    () => null,
  );
  if (
    lexicalBefore === null ||
    lexicalBefore.isSymbolicLink() ||
    !lexicalBefore.isFile()
  ) {
    throw new Error(`ACPX ${agent} executable must be a real regular file`);
  }
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(
      commandPath,
      verifiedExecutableOpenFlags(process.platform, constants.O_NOFOLLOW),
    );
  } catch {
    throw new Error(
      `ACPX ${agent} executable could not be opened as a no-follow regular file`,
    );
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.size < 1n ||
      before.size > BigInt(MAX_AGENT_COMMAND_BYTES)
    ) {
      throw new Error(
        `ACPX ${agent} executable must be a bounded regular file`,
      );
    }
    const bytes = await readHandleAtStart(handle, Number(before.size));
    const after = await handle.stat({ bigint: true });
    const lexicalAfter = await lstat(commandPath, { bigint: true }).catch(
      () => null,
    );
    const beforeIdentity = fileIdentity(before);
    const afterIdentity = fileIdentity(after);
    if (
      bytes.length < 1 ||
      bytes.length > MAX_AGENT_COMMAND_BYTES ||
      lexicalAfter === null ||
      lexicalAfter.isSymbolicLink() ||
      !lexicalAfter.isFile() ||
      !sameIdentity(fileIdentity(lexicalBefore), fileIdentity(lexicalAfter)) ||
      !sameIdentity(fileIdentity(lexicalAfter), afterIdentity) ||
      !sameIdentity(beforeIdentity, afterIdentity) ||
      after.size !== BigInt(bytes.length)
    ) {
      throw new Error(`ACPX ${agent} executable changed while it was verified`);
    }
    const digest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    if (digest !== expectedDigest) {
      throw new Error(`ACPX ${agent} executable digest mismatch`);
    }
    return { bytes, digest, identity: afterIdentity };
  } catch (error) {
    throw error;
  } finally {
    await handle.close();
  }
}

/** Fail closed where Node cannot atomically refuse a final symlink component. */
export function verifiedExecutableOpenFlags(
  platform: NodeJS.Platform,
  noFollowFlag: number | undefined,
): number {
  if (
    platform === "win32" ||
    typeof noFollowFlag !== "number" ||
    noFollowFlag === 0
  ) {
    throw new Error(
      "ACPX verified executable launch requires atomic no-follow file opening",
    );
  }
  return constants.O_RDONLY | noFollowFlag;
}

async function openVerifiedCommandDirectory(
  commandDirectory: string,
  agent: string,
): Promise<{
  handle: FileHandle;
  identity: VerifiedAcpxDirectoryIdentity;
}> {
  const lexicalBefore = await lstat(commandDirectory, { bigint: true }).catch(
    () => null,
  );
  if (
    lexicalBefore === null ||
    lexicalBefore.isSymbolicLink() ||
    !lexicalBefore.isDirectory()
  ) {
    throw new Error(
      `ACPX ${agent} executable directory must be a real directory`,
    );
  }
  let handle: FileHandle;
  try {
    handle = await open(
      commandDirectory,
      verifiedDirectoryOpenFlags(
        process.platform,
        constants.O_NOFOLLOW,
        constants.O_DIRECTORY,
      ),
    );
  } catch {
    throw new Error(
      `ACPX ${agent} executable directory could not be opened as a no-follow directory`,
    );
  }
  try {
    const opened = await handle.stat({ bigint: true });
    const lexicalAfter = await lstat(commandDirectory, { bigint: true }).catch(
      () => null,
    );
    const beforeIdentity = directoryIdentity(lexicalBefore);
    const openedIdentity = directoryIdentity(opened);
    if (
      !opened.isDirectory() ||
      lexicalAfter === null ||
      lexicalAfter.isSymbolicLink() ||
      !lexicalAfter.isDirectory() ||
      !sameDirectoryIdentity(beforeIdentity, directoryIdentity(lexicalAfter)) ||
      !sameDirectoryIdentity(directoryIdentity(lexicalAfter), openedIdentity)
    ) {
      throw new Error(
        `ACPX ${agent} executable directory changed while it was verified`,
      );
    }
    return { handle, identity: openedIdentity };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function inspectDependencyAncestors(
  commandDirectory: string,
  agent: string,
): Promise<VerifiedAcpxDependencyAncestor[]> {
  const ancestors: VerifiedAcpxDependencyAncestor[] = [];
  let ancestor = dirname(commandDirectory);
  for (let count = 0; count < MAX_DEPENDENCY_ANCESTORS; count += 1) {
    const verified = await openVerifiedCommandDirectory(ancestor, agent);
    ancestors.push({ path: ancestor, identity: verified.identity });
    await verified.handle.close();
    const parent = dirname(ancestor);
    if (parent === ancestor) return ancestors;
    ancestor = parent;
  }
  throw new Error("ACPX provider dependency ancestry exceeds its bound");
}

async function openDependencyAncestors(
  ancestors: readonly VerifiedAcpxDependencyAncestor[],
): Promise<FileHandle[]> {
  const handles: FileHandle[] = [];
  try {
    for (const expected of ancestors) {
      const current = await openVerifiedCommandDirectory(
        expected.path,
        "provider dependency ancestor",
      );
      if (!sameDirectoryIdentity(current.identity, expected.identity)) {
        await current.handle.close();
        throw new Error(
          "ACPX provider dependency ancestor identity changed after verification",
        );
      }
      handles.push(current.handle);
    }
    return handles;
  } catch (error) {
    await Promise.all(handles.map((handle) => handle.close()));
    throw error;
  }
}

/** Fail closed where Node cannot atomically pin a real directory inode. */
function verifiedDirectoryOpenFlags(
  platform: NodeJS.Platform,
  noFollowFlag: number | undefined,
  directoryFlag: number | undefined,
): number {
  if (
    platform === "win32" ||
    typeof noFollowFlag !== "number" ||
    noFollowFlag === 0 ||
    typeof directoryFlag !== "number" ||
    directoryFlag === 0
  ) {
    throw new Error(
      "ACPX verified executable launch requires atomic no-follow directory opening",
    );
  }
  return constants.O_RDONLY | noFollowFlag | directoryFlag;
}

async function readHandleAtStart(
  handle: FileHandle,
  size: number,
): Promise<Buffer> {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const read = await handle.read(bytes, offset, size - offset, offset);
    if (read.bytesRead === 0) break;
    offset += read.bytesRead;
  }
  if (offset !== size) {
    throw new Error("ACPX provider executable ended during verification");
  }
  return bytes;
}

function commandLease(
  commandDirectoryPath: string,
  commandName: string,
  format: AcpxCommandFormat,
  verifiedBytes: Buffer,
  commandDirectory: FileHandle,
  dependencyAncestors: readonly FileHandle[],
): VerifiedAcpxCommandLease {
  let consumed = false;
  let directoriesReleased = false;
  const releaseDirectories = async (): Promise<void> => {
    if (directoriesReleased) return;
    directoriesReleased = true;
    await Promise.all([
      commandDirectory.close(),
      ...dependencyAncestors.map((handle) => handle.close()),
    ]);
  };
  const releaseDirectoriesBestEffort = (): void => {
    void releaseDirectories().catch(() => undefined);
  };
  const close = async (): Promise<void> => {
    if (consumed) return;
    consumed = true;
    verifiedBytes.fill(0);
    await releaseDirectories();
  };
  return {
    spawn(
      args: readonly string[] = [],
      options: SpawnOptionsWithoutStdio = {},
      lifetime?: VerifiedAcpxProviderLifetime,
    ): ChildProcess {
      if (consumed) throw new Error("Verified ACPX command lease is closed");
      consumed = true;
      let child: ChildProcess;
      try {
        const providerBootstrap =
          format === "module"
            ? MODULE_SNAPSHOT_BOOTSTRAP
            : COMMONJS_SNAPSHOT_BOOTSTRAP;
        const guarded = lifetime !== undefined;
        const providerOwnershipFd =
          DEPENDENCY_ANCESTOR_FD_START + dependencyAncestors.length + 1;
        if (
          guarded &&
          (!Number.isSafeInteger(lifetime.credentialFenceFd) ||
            lifetime.credentialFenceFd < 0 ||
            typeof lifetime.activateCredentialFenceOwner !== "function")
        ) {
          throw new Error("ACPX provider credential fence is invalid");
        }
        child = spawnChildProcess(
          process.execPath,
          guarded
            ? [
                "--eval",
                PROVIDER_LIFETIME_GUARDIAN_SOURCE,
                providerBootstrap,
                commandDirectoryPath,
                commandName,
                String(dependencyAncestors.length),
                ...args,
              ]
            : [
                "--eval",
                providerBootstrap,
                commandDirectoryPath,
                commandName,
                String(dependencyAncestors.length),
                ...args,
              ],
          {
            ...options,
            // In production this process is a persistent sentinel and group
            // leader. It arms owner-death before spawning provider code, keeps
            // the credential listener inherited, and pins the PGID until its
            // single whole-group reap.
            detached: process.platform !== "win32",
            env: sanitizedNodeEnvironment(options.env),
            shell: false,
            stdio: guarded
              ? [
                  "pipe",
                  "pipe",
                  "pipe",
                  "pipe",
                  commandDirectory.fd,
                  ...dependencyAncestors.map((handle) => handle.fd),
                  "pipe",
                  "pipe",
                  lifetime.credentialFenceFd,
                ]
              : [
                  "pipe",
                  "pipe",
                  "pipe",
                  "pipe",
                  commandDirectory.fd,
                  ...dependencyAncestors.map((handle) => handle.fd),
                ],
          },
        );
        if (guarded) {
          protectProviderGroupKill(child);
          const guardianPid = child.pid!;
          const ownership = Promise.all([
            providerOwnershipHandshake(child, providerOwnershipFd),
            Promise.resolve().then(() =>
              lifetime.activateCredentialFenceOwner(guardianPid),
            ),
          ]).then(() => undefined);
          // Session construction can reject before the adapter reaches its
          // explicit ownership await. Observe that early rejection now while
          // preserving it for the admission boundary.
          void ownership.catch(() => undefined);
          providerGuardianOwnership.set(child, ownership);
        }
      } catch (error) {
        verifiedBytes.fill(0);
        releaseDirectoriesBestEffort();
        throw error;
      }
      releaseDirectoriesBestEffort();
      const sourceInput = child.stdio[COMMAND_SOURCE_FD] as Writable | null;
      if (sourceInput === null) {
        verifiedBytes.fill(0);
        child.kill();
        throw new Error("Verified ACPX command source pipe was not created");
      }
      const release = (): void => {
        verifiedBytes.fill(0);
      };
      sourceInput.once("error", release);
      sourceInput.end(verifiedBytes, release);
      return child;
    },
    close,
  };
}

function protectProviderGroupKill(child: ChildProcess): void {
  const processGroupId = child.pid;
  if (!Number.isSafeInteger(processGroupId) || (processGroupId ?? 0) <= 0) {
    throw new Error(
      "ACPX provider lifetime guardian omitted its group identity",
    );
  }
  const signalGuardian = child.kill.bind(child);
  let groupReaped = false;
  child.kill = (signal?: NodeJS.Signals | number): boolean => {
    if (signal !== "SIGKILL" && signal !== 9) {
      return signalGuardian(signal);
    }
    if (groupReaped) return false;
    try {
      // The live sentinel pins this PGID. ACPX may request an emergency KILL,
      // but it must never kill only the fence owner or signal a reused group.
      process.kill(-(processGroupId as number), "SIGKILL");
      groupReaped = true;
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") {
        groupReaped = true;
        return false;
      }
      throw error;
    }
  };
}

function providerOwnershipHandshake(
  child: ChildProcess,
  ownershipFd: number,
): Promise<void> {
  const output = (child.stdio as Array<Readable | Writable | null | undefined>)[
    ownershipFd
  ] as Readable | null | undefined;
  if (output == null) {
    return Promise.reject(
      new Error("ACPX provider lifetime guardian omitted its ownership pipe"),
    );
  }
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    let buffered = "";
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.off("error", onError);
      child.off("close", onClose);
      output.off("data", onData);
      if (error) reject(error);
      else resolve();
    };
    const onError = (): void =>
      finish(new Error("ACPX provider lifetime guardian failed to start"));
    const onClose = (): void =>
      finish(
        new Error(
          "ACPX provider lifetime guardian exited before ownership transfer",
        ),
      );
    const onData = (chunk: Buffer | string): void => {
      buffered += chunk.toString();
      if (buffered.includes("owned\n")) finish();
    };
    const timer = setTimeout(
      () =>
        finish(
          new Error("ACPX provider lifetime guardian ownership timed out"),
        ),
      PROVIDER_GUARDIAN_HANDSHAKE_TIMEOUT_MS,
    );
    timer.unref();
    child.once("error", onError);
    child.once("close", onClose);
    output.on("data", onData);
  });
}

function sanitizedNodeEnvironment(
  environment: NodeJS.ProcessEnv | undefined,
): NodeJS.ProcessEnv {
  const sanitized = { ...(environment ?? process.env) };
  for (const key of Object.keys(sanitized)) {
    // Environment keys are case-insensitive on Windows. Dropping every case
    // variant also keeps a context portable instead of admitting a preload on
    // one runner host and rejecting it on another.
    if (key.toUpperCase() === "NODE_OPTIONS") delete sanitized[key];
  }
  return sanitized;
}

function snapshotBootstrap(format: AcpxCommandFormat): string {
  return [
    'const fs = require("node:fs");',
    'const { isBuiltin, registerHooks } = require("node:module");',
    'const { resolve } = require("node:path");',
    'const { fileURLToPath, pathToFileURL } = require("node:url");',
    "const commandDirectory = process.argv[1];",
    "const commandName = process.argv[2];",
    "const dependencyAncestorCount = Number.parseInt(process.argv[3], 10);",
    `if (!Number.isSafeInteger(dependencyAncestorCount) || dependencyAncestorCount < 1 || dependencyAncestorCount > ${MAX_DEPENDENCY_ANCESTORS}) throw new Error("ACPX provider dependency ancestry is invalid");`,
    "const commandPath = resolve(commandDirectory, commandName);",
    "process.argv.splice(1, 3, commandPath);",
    `const guardSnapshotModuleLookup = ${guardSnapshotModuleLookup.toString()};`,
    `const directory = process.platform === "linux" ? "/proc/self/fd/${COMMAND_DIRECTORY_FD}" : commandDirectory;`,
    "const directoryUrl = pathToFileURL(`${directory}/`).href;",
    "const pinnedTarget = new URL(commandName, directoryUrl).href;",
    `const dependencyDirectoryUrls = Array.from({ length: dependencyAncestorCount }, (_, index) => pathToFileURL("/proc/self/fd/" + (${DEPENDENCY_ANCESTOR_FD_START} + index) + "/").href);`,
    "const target = pathToFileURL(commandPath).href;",
    "const dependencyAncestorByUrl = new Map([[target, 0]]);",
    "const dependencyAncestorIndex = (url) => { const recorded = dependencyAncestorByUrl.get(url); if (recorded !== undefined) return recorded; return dependencyDirectoryUrls.findIndex((dependencyDirectoryUrl) => url?.startsWith(dependencyDirectoryUrl) === true); };",
    "const rememberDependencyAncestor = (resolution, fallbackIndex) => { const resolvedIndex = dependencyAncestorIndex(resolution?.url); const index = resolvedIndex < 0 ? fallbackIndex : resolvedIndex; if (index >= 0 && typeof resolution?.url === \"string\") dependencyAncestorByUrl.set(resolution.url, index); return resolution; };",
    `const source = fs.readFileSync(${COMMAND_SOURCE_FD});`,
    "registerHooks({ resolve(specifier, context, nextResolve) {",
    "if (specifier === target) return { url: target, shortCircuit: true };",
    "const entryImport = context.parentURL === target;",
    "const parentDependencyAncestorIndex = entryImport ? 0 : dependencyAncestorIndex(context.parentURL);",
    'const entryRelative = entryImport && (specifier.startsWith("./") || specifier.startsWith("../"));',
    "const pinnedSpecifier = entryRelative ? new URL(specifier, pinnedTarget) : null;",
    'const lookupSpecifier = pinnedSpecifier === null ? specifier : context.conditions?.includes("require") ? fileURLToPath(pinnedSpecifier) : pinnedSpecifier.href;',
    "const snapshotImport = entryImport || context.parentURL?.startsWith(directoryUrl) === true || dependencyDirectoryUrls.some((dependencyDirectoryUrl) => context.parentURL?.startsWith(dependencyDirectoryUrl) === true);",
    "const filesystemLookup = snapshotImport && !isBuiltin(specifier);",
    "const lookupContext = entryImport && pinnedSpecifier === null && !isBuiltin(specifier) ? { ...context, parentURL: pinnedTarget } : context;",
    "return guardSnapshotModuleLookup(process.platform, filesystemLookup, () => {",
    "try { return rememberDependencyAncestor(nextResolve(lookupSpecifier, lookupContext), parentDependencyAncestorIndex); } catch (error) {",
    'if (!snapshotImport || pinnedSpecifier !== null || isBuiltin(specifier) || error?.code !== "ERR_MODULE_NOT_FOUND") throw error;',
    "let dependencyError = error;",
    "for (let dependencyIndex = Math.max(0, parentDependencyAncestorIndex); dependencyIndex < dependencyDirectoryUrls.length; dependencyIndex += 1) {",
    "const dependencyDirectoryUrl = dependencyDirectoryUrls[dependencyIndex];",
    'try { return rememberDependencyAncestor(nextResolve(specifier, { ...context, parentURL: new URL("package.json", dependencyDirectoryUrl).href }), dependencyIndex); } catch (candidateError) {',
    'if (candidateError?.code !== "ERR_MODULE_NOT_FOUND") throw candidateError;',
    "dependencyError = candidateError;",
    "}",
    "}",
    "throw dependencyError;",
    "}",
    "});",
    "}, load(url, context, nextLoad) {",
    `if (url === target) return { format: ${JSON.stringify(format)}, source, shortCircuit: true };`,
    "const descriptorLookup = url.startsWith(directoryUrl) || dependencyDirectoryUrls.some((dependencyDirectoryUrl) => url.startsWith(dependencyDirectoryUrl));",
    "return guardSnapshotModuleLookup(process.platform, descriptorLookup, () => nextLoad(url, context));",
    "} });",
    "import(target).catch((error) => { console.error(error); process.exitCode = 1; });",
  ].join("");
}

export function guardSnapshotModuleLookup<T>(
  platform: NodeJS.Platform,
  filesystemLookup: boolean,
  lookup: () => T,
): T {
  if (platform !== "linux" && filesystemLookup) {
    throw new Error(
      "ACPX provider relative module loading requires Linux descriptor-pinned paths",
    );
  }
  return lookup();
}

function executableFormat(
  relativeCommand: string,
  packageType: unknown,
  agent: string,
): AcpxCommandFormat {
  const extension = extname(relativeCommand);
  if (extension === ".mjs") return "module";
  if (extension === ".cjs") return "commonjs";
  if (extension === ".js") {
    if (packageType === undefined || packageType === "commonjs") {
      return "commonjs";
    }
    if (packageType === "module") return "module";
  }
  throw new Error(`ACPX ${agent} package exposes an unsupported executable`);
}

function fileIdentity(metadata: {
  dev: bigint;
  ino: bigint;
  size: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
}): VerifiedAcpxCommandIdentity {
  return {
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
    size: metadata.size.toString(),
    modifiedNanoseconds: metadata.mtimeNs.toString(),
    changedNanoseconds: metadata.ctimeNs.toString(),
  };
}

function directoryIdentity(metadata: {
  dev: bigint;
  ino: bigint;
}): VerifiedAcpxDirectoryIdentity {
  return {
    device: metadata.dev.toString(),
    inode: metadata.ino.toString(),
  };
}

function sameDirectoryIdentity(
  left: VerifiedAcpxDirectoryIdentity,
  right: VerifiedAcpxDirectoryIdentity,
): boolean {
  return left.device === right.device && left.inode === right.inode;
}

function sameIdentity(
  left: VerifiedAcpxCommandIdentity,
  right: VerifiedAcpxCommandIdentity,
): boolean {
  return (
    left.device === right.device &&
    left.inode === right.inode &&
    left.size === right.size &&
    left.modifiedNanoseconds === right.modifiedNanoseconds &&
    left.changedNanoseconds === right.changedNanoseconds
  );
}

function oneExecutable(value: unknown, agent: string): string {
  const candidates =
    typeof value === "string"
      ? [value]
      : typeof value === "object" && value !== null && !Array.isArray(value)
        ? Object.values(value).filter(
            (candidate): candidate is string => typeof candidate === "string",
          )
        : [];
  const unique = Array.from(new Set(candidates));
  if (
    unique.length !== 1 ||
    unique[0]!.length === 0 ||
    unique[0]!.includes("\0") ||
    isAbsolute(unique[0]!)
  ) {
    throw new Error(
      `ACPX ${agent} package must expose one relative executable`,
    );
  }
  return unique[0]!;
}

function isInside(parent: string, child: string): boolean {
  const relativePath = relative(resolve(parent), resolve(child));
  return (
    relativePath.length > 0 &&
    relativePath !== ".." &&
    !relativePath.startsWith(
      `..${process.platform === "win32" ? "\\" : "/"}`,
    ) &&
    !isAbsolute(relativePath)
  );
}

function isInsideOrEqual(parent: string, child: string): boolean {
  return resolve(parent) === resolve(child) || isInside(parent, child);
}

import {
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import FullSystemScan, { type SystemView } from "./FullSystemScan";
import fixture from "./__fixtures__/samples.json";
import { checksComplete, type ScanReport } from "./report";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
  isTauri: () => true,
}));
const mockInvoke = vi.mocked(invoke);
const sample = fixture as ScanReport;
let current: SystemView | null;
const finishedReport = () => ({
  ...sample,
  cancelled: false,
  roots: [
    {
      path: { display: "C:\\" },
      status: sample.status,
      verdict: sample.verdict,
      summary: sample.summary,
    },
  ],
  excluded_working_directories: [],
});
const runningView = (): SystemView => ({
  schema_version: 1,
  id: 7,
  phase: "running",
  targets: ["C:\\"],
  current_path: "C:\\large-file.exe",
  files: 6,
  detections: 4,
  skipped: 0,
  failed: 0,
  incomplete: 0,
  issues: 0,
  bytes_read: 65536,
  elapsed_ms: 1500,
  error: null,
  report: null,
  sources: { rules: sample.rules, hash_database: sample.hash_database },
});

afterEach(cleanup);
beforeEach(() => {
  current = null;
  mockInvoke.mockReset();
  mockInvoke.mockImplementation(async (command, args) => {
    const params = args as Record<string, unknown>;
    switch (command) {
      case "list_scan_drives":
        return [
          { id: "C", path: "C:\\" },
          { id: "D", path: "D:\\" },
        ];
      case "system_scan_status":
        return current;
      case "start_system_scan":
        current = runningView();
        return current;
      case "cancel_system_scan":
        current = {
          ...current!,
          phase: "cancelled",
          report: { ...finishedReport(), status: "partial", cancelled: true },
        };
        return;
      case "system_scan_detail":
        return sample.files[Number(params.id) - 1];
      case "export_system_scan":
        return "C:\\reports\\full.json";
      case "system_scan_page": {
        if (params.issues) return { page: params.page, total: 0, rows: [] };
        const rows = sample.files
          .map((file, index) => ({
            id: index + 1,
            path: file.path,
            metadata: file.metadata,
            verdict: file.verdict,
            status: file.status,
            complete: checksComplete(file),
          }))
          .filter(
            (file) =>
              params.filter === "all" ||
              (params.filter === "detections"
                ? ["suspicious", "known_malicious_match"].includes(file.verdict)
                : file.verdict === params.filter),
          );
        return { page: params.page, total: 201, rows };
      }
      default:
        throw new Error(`Unexpected command: ${command}`);
    }
  });
});

describe("full-system scan workflow", () => {
  it("discovers drives and passes selected IDs, then shows live progress and cancellation", async () => {
    const user = userEvent.setup();
    const busy = vi.fn();
    render(<FullSystemScan onBusyChange={busy} />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Start full-system scan" }),
      ).toBeEnabled(),
    );
    await user.click(screen.getByRole("checkbox", { name: "D:\\" }));
    await user.click(
      screen.getByRole("button", { name: "Start full-system scan" }),
    );
    expect(mockInvoke).toHaveBeenCalledWith("start_system_scan", {
      driveIds: ["C"],
    });
    expect(
      screen.getByRole("button", { name: "Start full-system scan" }),
    ).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("64.0 KiB read");
    expect(screen.getByRole("status")).toHaveTextContent("C:\\large-file.exe");
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel scan" }));
    expect(
      await screen.findByRole(
        "heading",
        { name: "Scan cancelled" },
        { timeout: 3000 },
      ),
    ).toBeVisible();
    expect(
      screen.getByText(/Cancellation preserved collected results/),
    ).toBeVisible();
    expect(screen.getByText("Coverage: partial")).toBeVisible();
    expect(screen.getAllByText("Known malicious match").length).toBeGreaterThan(
      0,
    );
    expect(busy).toHaveBeenLastCalledWith(false);
  });

  it("pages backend results, requests details by ID, and exports the retained session", async () => {
    current = { ...runningView(), phase: "finished", report: finishedReport() };
    const user = userEvent.setup();
    render(<FullSystemScan onBusyChange={vi.fn()} />);
    await screen.findByRole("heading", { name: "Scan finished" });
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Filter system results" }),
      "all",
    );
    const results = screen.getByRole("region", { name: "System file results" });
    const marker = await within(results).findByRole("button", {
      name: /test-marker.txt/,
    });
    await user.click(marker);
    expect(
      await screen.findByRole("complementary", { name: "File details" }),
    ).toHaveTextContent("SHA-256");
    expect(mockInvoke).toHaveBeenCalledWith("system_scan_detail", {
      sessionId: 7,
      id:
        sample.files.findIndex((file) =>
          file.path.display.endsWith("test-marker.txt"),
        ) + 1,
    });
    await user.click(screen.getByRole("button", { name: "Next files" }));
    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("system_scan_page", {
        sessionId: 7,
        query: "",
        filter: "all",
        page: 1,
        issues: false,
      }),
    );
    await user.click(
      screen.getByRole("button", { name: "Export system JSON" }),
    );
    expect(mockInvoke).toHaveBeenCalledWith("export_system_scan", {
      sessionId: 7,
    });
    expect(screen.getByText(/Report exported to/)).toBeVisible();
  });

  it("shows source failures immediately while a scan is still running", async () => {
    current = {
      ...runningView(),
      sources: {
        rules: {
          status: "failed",
          error: { kind: "invalid_rules", message: "Invalid custom rules" },
        },
        hash_database: sample.hash_database,
      },
    };
    render(<FullSystemScan onBusyChange={vi.fn()} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "YARA source error: Invalid custom rules",
    );
    expect(screen.getByText("Assessment pending")).toBeVisible();
  });

  it("does not invent a successful report when starting the worker fails", async () => {
    current = { ...runningView(), phase: "finished", report: finishedReport() };
    const original = mockInvoke.getMockImplementation()!;
    mockInvoke.mockImplementation((command, args, options) =>
      command === "start_system_scan"
        ? Promise.reject("Result storage is unavailable")
        : original(command, args, options),
    );
    const user = userEvent.setup();
    render(<FullSystemScan onBusyChange={vi.fn()} />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Start full-system scan" }),
      ).toBeEnabled(),
    );
    await user.click(
      screen.getByRole("button", { name: "Start full-system scan" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Result storage is unavailable",
    );
    expect(
      screen.queryByRole("heading", { name: "Scan finished" }),
    ).not.toBeInTheDocument();
  });
});

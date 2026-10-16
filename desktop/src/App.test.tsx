import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import App from "./App";
import fixture from "./__fixtures__/samples.json";
import type { ScanReport } from "./report";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
  isTauri: () => true,
}));
const mockInvoke = vi.mocked(invoke);
const report = fixture as ScanReport;

afterEach(cleanup);
beforeEach(() => mockInvoke.mockReset());

async function scanFixture(value = report) {
  const user = userEvent.setup();
  mockInvoke
    .mockResolvedValueOnce("C:\\samples\\files")
    .mockResolvedValueOnce(value);
  render(<App />);
  await user.click(screen.getByRole("button", { name: "Choose folder" }));
  await user.click(screen.getByRole("button", { name: "Start scan →" }));
  await screen.findByRole("heading", { name: "Analysis results" });
  return user;
}

describe("desktop scan workflow", () => {
  it("keeps checked-in scan fixtures free of local paths and file timestamps", () => {
    expect(report.target).toEqual({ display: "C:\\samples\\files" });
    for (const file of report.files) {
      const name = file.path.display.split("\\").at(-1)!;
      expect(file.path).toEqual({ display: `C:\\samples\\files\\${name}` });
      expect(file.metadata?.modified_unix_ms).toBeNull();
    }
    expect(report.issues).toEqual([]);
    if (report.rules.status === "ready") {
      for (const source of report.rules.info.sources) {
        expect(source.path).toEqual({
          display: expect.stringMatching(/^rules\/[a-z_]+\.yar$/),
        });
      }
    }
    if (report.hash_database.status === "ready") {
      expect(report.hash_database.info.path).toEqual({
        display: "indicators/known_hashes.json",
      });
    }
  });

  it("requires selection, then displays actual engine verdicts and rule authors", async () => {
    const user = userEvent.setup();
    mockInvoke.mockResolvedValueOnce(null);
    const view = render(<App />);
    expect(screen.getByRole("button", { name: "Start scan →" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Choose file" }));
    expect(screen.getByRole("button", { name: "Start scan →" })).toBeDisabled();
    view.unmount();
    await scanFixture();
    const files = screen.getByRole("region", { name: "File results" });
    expect(within(files).getAllByRole("row")).toHaveLength(7);
    await user.click(
      screen.getByRole("button", { name: /synthetic-alienspy.txt/ }),
    );
    await user.click(screen.getByRole("tab", { name: "Detections" }));
    const match = report.files.find((f) =>
      f.path.display.endsWith("synthetic-alienspy.txt"),
    )!.signatures;
    if (match?.status !== "complete")
      throw new Error("Fixture must contain a complete YARA check");
    expect(
      screen.getByRole("tabpanel", { name: "Detections" }),
    ).toHaveTextContent(match.matches[0].author);
    expect(screen.getAllByText("Known malicious match").length).toBeGreaterThan(
      0,
    );
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Filter results" }),
      "test_match",
    );
    expect(within(files).getAllByRole("row")).toHaveLength(2);
    expect(
      within(files).getByRole("button", { name: /test-marker.txt/ }),
    ).toBeVisible();
    await user.type(
      screen.getByRole("textbox", { name: "Search file paths" }),
      "missing",
    );
    expect(
      within(files).getByText("No files match this filter."),
    ).toBeVisible();
  });

  it("keeps positive evidence visible when the report is partial", async () => {
    const partial = structuredClone(report);
    partial.status = "partial";
    partial.issues = [
      {
        path: { display: "C:\\denied" },
        error: {
          kind: "PermissionDenied",
          operation: "read_directory",
          message: "Access denied",
        },
      },
    ];
    await scanFixture(partial);
    expect(screen.getByText("partial")).toBeVisible();
    expect(screen.getAllByText("Known malicious match").length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText(/Access denied/)).toBeVisible();
    expect(screen.getByText(/Some checks did not complete/)).toBeVisible();
  });

  it("shows honest activity, prevents duplicate scans, and reports IPC errors", async () => {
    const user = userEvent.setup();
    let rejectScan: (reason: string) => void = () => {};
    mockInvoke.mockResolvedValueOnce("C:\\target").mockImplementationOnce(
      () =>
        new Promise((_resolve, reject) => {
          rejectScan = reject;
        }),
    );
    render(<App />);
    await user.click(screen.getByRole("button", { name: "Choose folder" }));
    await user.click(screen.getByRole("button", { name: "Start scan →" }));
    expect(screen.getByRole("status")).toHaveTextContent(
      "Inspecting selected files",
    );
    expect(screen.getByRole("button", { name: "Scanning…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Choose file" })).toBeDisabled();
    rejectScan("Scan worker failed");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Scan worker failed",
    );
    expect(
      screen.queryByRole("heading", { name: "Analysis results" }),
    ).not.toBeInTheDocument();
  });

  it("exports using the retained backend report without sending paths or JSON", async () => {
    const user = await scanFixture();
    mockInvoke.mockResolvedValueOnce("C:\\reports\\scan.json");
    await user.click(screen.getByRole("button", { name: "Export JSON ↗" }));
    expect(mockInvoke).toHaveBeenLastCalledWith("export_report");
    expect(screen.getByRole("status")).toHaveTextContent("Report exported");
  });

  it("shows an empty folder without presenting it as proof of safety", async () => {
    const empty = structuredClone(report);
    empty.files = [];
    empty.verdict = "no_detections";
    for (const key of Object.keys(
      empty.summary,
    ) as (keyof ScanReport["summary"])[])
      empty.summary[key] = 0;
    await scanFixture(empty);
    expect(
      screen.getByText("This scan found no regular files to inspect."),
    ).toBeVisible();
    expect(
      screen.getByText("No file entries. Review scan issues below."),
    ).toBeVisible();
  });

  it("uses custom sources only through explicit native selection", async () => {
    const user = userEvent.setup();
    mockInvoke
      .mockResolvedValueOnce("C:\\my-rules")
      .mockResolvedValueOnce(undefined);
    render(<App />);
    await user.click(screen.getByText("Detection sources"));
    await user.click(screen.getByRole("button", { name: "Change folder" }));
    expect(mockInvoke).toHaveBeenLastCalledWith("choose_path", {
      kind: "rules",
    });
    await user.click(screen.getByRole("button", { name: "Use bundled" }));
    expect(mockInvoke).toHaveBeenLastCalledWith("clear_override", {
      kind: "rules",
    });
  });

  it("shows PE observations and flags integers beyond exact UI precision", async () => {
    const pe = structuredClone(report);
    pe.files = [
      pe.files.find((file) => file.path.display.endsWith("clean.txt"))!,
    ];
    pe.files[0].pe = {
      status: "analyzed",
      report: {
        format: "pe32_plus",
        machine: 34404,
        architecture: "x86_64",
        is_dll: false,
        coff_timestamp: 0,
        characteristics: 0,
        subsystem: 3,
        dll_characteristics: 0,
        entry_point_rva: 4096,
        image_base: 2 ** 60,
        size_of_image: 8192,
        size_of_headers: 512,
        section_alignment: 4096,
        file_alignment: 512,
        sections: [
          {
            name: ".text",
            raw_size: 512,
            virtual_size: 100,
            virtual_address: 4096,
            raw_offset: 512,
            characteristics: 0,
            readable: true,
            writable: false,
            executable: true,
            entropy: 1.75,
          },
        ],
        imports: [
          {
            dll: "KERNEL32.dll",
            symbols: [
              { kind: "name", name: "GetProcAddress", hint: 0 },
              { kind: "ordinal", ordinal: 7 },
            ],
          },
        ],
      },
    };
    const user = await scanFixture(pe);
    await user.click(screen.getByRole("tab", { name: "PE analysis" }));
    const panel = screen.getByRole("tabpanel", { name: "PE analysis" });
    expect(panel).toHaveTextContent(".text");
    expect(panel).toHaveTextContent("1.750");
    expect(panel).toHaveTextContent("Exceeds UI integer precision");
    await user.click(within(panel).getByText("KERNEL32.dll"));
    expect(within(panel).getByText("GetProcAddress")).toBeVisible();
    expect(within(panel).getByText("Ordinal 7")).toBeVisible();
  });
});

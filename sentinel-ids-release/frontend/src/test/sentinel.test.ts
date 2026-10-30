import { describe, expect, it } from "vitest";
import { analyzeCsv, defaultRules } from "@/lib/sentinel";
describe("CSV rule detection", () => {
  it("flags real CSV threshold violations without claiming ML inference", () => {
    const rows = analyzeCsv(
      "Source IP,Destination IP,Flow Packets/s,SYN Flag Count\n192.168.1.1,10.0.0.1,2000,200\n192.168.1.2,10.0.0.2,20,1",
      defaultRules,
    );
    expect(rows).toHaveLength(2);
    expect(rows[0]?.attack).toBe("SYN Flood");
    expect(rows[0]?.engine).toBe("Rules only");
    expect(rows[1]?.attack).toBe("Benign");
  });
  it("requires rate features", () =>
    expect(() => analyzeCsv("foo,bar\n1,2", defaultRules)).toThrow("Missing required column"));
  it("rejects invalid numeric values", () =>
    expect(() => analyzeCsv("packet_rate\nInfinity", defaultRules)).toThrow("Invalid packet rate"));
  it("honors disabled rules", () =>
    expect(
      analyzeCsv("packet_rate,syn_count\n5000,500", { ...defaultRules, enabled: false })[0]?.attack,
    ).toBe("Benign"));
  it("handles quoted headers and values", () =>
    expect(
      analyzeCsv('"Source IP","Flow Packets/s"\n"192.168.1.1",1500', defaultRules)[0]?.source,
    ).toBe("192.168.1.1"));
});

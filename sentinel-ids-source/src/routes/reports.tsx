import { createFileRoute } from "@tanstack/react-router";
import { ReportsPage } from "@/components/sentinel/tools";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/reports")({
  head: () =>
    pageHead("Security reports", "Export the Sentinel monitoring session and security findings."),
  component: ReportsPage,
});

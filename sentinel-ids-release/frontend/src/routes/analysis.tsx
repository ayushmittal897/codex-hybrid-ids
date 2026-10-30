import { createFileRoute } from "@tanstack/react-router";
import { AnalysisPage } from "@/components/sentinel/tools";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/analysis")({
  head: () =>
    pageHead(
      "Dataset analysis",
      "Analyze network-flow CSV datasets with configurable detection rules.",
    ),
  component: AnalysisPage,
});

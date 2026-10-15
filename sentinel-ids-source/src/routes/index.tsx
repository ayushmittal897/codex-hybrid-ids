import { createFileRoute } from "@tanstack/react-router";
import { Overview } from "@/components/sentinel/overview";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/")({
  head: () =>
    pageHead(
      "Security overview",
      "Network traffic monitoring, threat investigations and hybrid IDS readiness.",
    ),
  component: Overview,
});

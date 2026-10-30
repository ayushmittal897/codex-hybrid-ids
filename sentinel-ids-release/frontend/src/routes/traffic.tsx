import { createFileRoute } from "@tanstack/react-router";
import { TrafficPage } from "@/components/sentinel/traffic";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/traffic")({
  head: () => pageHead("Live traffic", "Inspect and search network flows in Sentinel IDS."),
  component: TrafficPage,
});

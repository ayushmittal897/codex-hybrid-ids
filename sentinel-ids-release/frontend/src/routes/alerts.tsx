import { createFileRoute } from "@tanstack/react-router";
import { TrafficPage } from "@/components/sentinel/traffic";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/alerts")({
  head: () =>
    pageHead("Threat alerts", "Investigate suspicious flows and acknowledge security alerts."),
  component: () => <TrafficPage alerts />,
});

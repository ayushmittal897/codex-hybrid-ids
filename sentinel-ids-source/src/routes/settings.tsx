import { createFileRoute } from "@tanstack/react-router";
import { SettingsPage } from "@/components/sentinel/tools";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/settings")({
  head: () =>
    pageHead("Detection rules", "Configure packet-rate and SYN-count detection thresholds."),
  component: SettingsPage,
});

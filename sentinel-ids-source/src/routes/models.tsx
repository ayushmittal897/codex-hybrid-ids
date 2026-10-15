import { createFileRoute } from "@tanstack/react-router";
import { ModelsPage } from "@/components/sentinel/tools";
import { pageHead } from "@/lib/sentinel";
export const Route = createFileRoute("/models")({
  head: () =>
    pageHead("Detection models", "Review classifier readiness and measured evaluation status."),
  component: ModelsPage,
});

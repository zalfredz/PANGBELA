import { Suspense } from "react";
import { LoadingState } from "@/components/ui";
import IncidentView from "./incident-view";

// The id is only known at request time, so the client view reads it inside Suspense
// (required with cacheComponents); the fallback doubles as the loading state.
export default function IncidentPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading incident…" />}>
      <IncidentView />
    </Suspense>
  );
}

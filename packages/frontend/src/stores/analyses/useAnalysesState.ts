import type { AnalysisResult } from "shared";
import { ref } from "vue";

type AnalysesState =
  | { type: "Idle" }
  | { type: "Loading" }
  | { type: "Error"; error: string }
  | { type: "Success"; analyses: AnalysisResult[] };

type Message =
  | { type: "Start" }
  | { type: "Error"; error: string }
  | { type: "Success"; analyses: AnalysisResult[] }
  | { type: "Clear" };

function transition(current: AnalysesState, message: Message): AnalysesState {
  switch (current.type) {
    case "Idle":
      if (message.type === "Start") return { type: "Loading" };
      if (message.type === "Success")
        return { type: "Success", analyses: message.analyses };
      return current;
    case "Loading":
      if (message.type === "Error")
        return { type: "Error", error: message.error };
      if (message.type === "Success")
        return { type: "Success", analyses: message.analyses };
      return current;
    case "Error":
      if (message.type === "Start") return { type: "Loading" };
      if (message.type === "Success")
        return { type: "Success", analyses: message.analyses };
      if (message.type === "Clear") return { type: "Idle" };
      return current;
    case "Success":
      if (message.type === "Success")
        return { type: "Success", analyses: message.analyses };
      if (message.type === "Start") return { type: "Loading" };
      if (message.type === "Clear") return { type: "Idle" };
      return current;
    default:
      return current;
  }
}

export function useAnalysesState() {
  const state = ref<AnalysesState>({ type: "Idle" });

  const send = (message: Message) => {
    state.value = transition(state.value, message);
  };

  return { state, send };
}

import type { SeverityLevel } from "shared";

export function getSeverityBadgeStyle(level: SeverityLevel): string {
  switch (level) {
    case "high":
      return "bg-red-500/20 text-red-400 border-red-500/30";
    case "medium":
      return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "low":
      return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "info":
      return "bg-surface-500/20 text-surface-400 border-surface-500/30";
  }
}

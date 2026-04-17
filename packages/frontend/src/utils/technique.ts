export function getTechniqueColor(technique: string): string {
  switch (technique) {
    case "JSONP":
      return "success";
    case "AngularJS":
      return "danger";
    case "Alpine.js":
      return "info";
    case "HTMX":
      return "warning";
    case "Hyperscript":
      return "secondary";
    case "Script Injection":
      return "danger";
    case "Event Handler":
      return "warning";
    case "Link Preload":
      return "info";
    case "Iframe Injection":
      return "danger";
    default:
      return "secondary";
  }
}

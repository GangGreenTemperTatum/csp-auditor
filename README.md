<div align="center">
  <img width="1000" alt="image" src="https://github.com/caido-community/.github/blob/main/content/banner.png?raw=true">

  <br />
  <br />
  <a href="https://github.com/caido-community" target="_blank">GitHub</a>
  <span>&nbsp;&nbsp;&bull;&nbsp;&nbsp;</span>
  <a href="https://developer.caido.io/" target="_blank">Documentation</a>
  <span>&nbsp;&nbsp;&bull;&nbsp;&nbsp;</span>
  <a href="https://links.caido.io/www-discord" target="_blank">Discord</a>
  <br />
  <hr />
</div>

# CSP Auditor

Content Security Policy vulnerability scanner and analyzer for Caido. Automatically detects CSP headers in HTTP responses, analyzes them against 20+ security checks, and reports findings with remediation guidance.

## Features

- Real-time CSP header detection via response interception
- 20+ vulnerability checks across 7 categories (Critical, Modern Threats, Missing Features, Policy Weaknesses, Style Issues, Legacy Issues, Advanced)
- Built-in CSP bypass database with 205 payloads from security research
- Configurable check presets (Aggressive, Recommended, Light)
- Export findings as JSON or CSV
- Scope-aware analysis (respects Caido project scope)
- Auto-creation of Caido findings for detected vulnerabilities

## Installation

### From Plugin Store

1. Open Caido
2. Navigate to **Plugins**
3. Search for "CSP Auditor"
4. Click **Install**

### Manual Installation

1. Install dependencies:

   ```bash
   pnpm install
   ```

2. Build the plugin:

   ```bash
   pnpm build
   ```

3. Install in Caido:
   - Upload the `plugin_package.zip` file by clicking "Install Package" in Caido's plugins tab.

## Usage

1. Browse to web applications that serve CSP headers
2. The plugin automatically intercepts responses and analyzes CSP policies
3. View results in the **Dashboard** tab with sortable columns
4. Expand rows to see individual findings with severity badges and remediation
5. Use the **Database** tab to search 205 bypass payloads
6. Configure which checks are active in the **Configuration** tab

## Contributing

Contributions are welcome! Please feel free to submit issues and enhancement requests.

## Acknowledgment

Originally created by [GangGreenTemperTatum](https://github.com/GangGreenTemperTatum).

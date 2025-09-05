# CSP Auditor

<div align="center">

_A comprehensive Content Security Policy (CSP) vulnerability scanner plugin for Caido, designed to automatically detect and analyze CSP headers for common security misconfigurations and vulnerabilities with easily available applicable gadgets._

Brought to you by [@GangGreenTemperTatum](https://github.com/GangGreenTemperTatum), proud ambassador of the [Caido](https://caido.io/ambassadors) community!

_Hack the planet 🤘_

[![GitHub forks](https://img.shields.io/github/forks/GangGreenTemperTatum/csp-auditor?style=social)](https://github.com/GangGreenTemperTatum/csp-auditor/network/members)
[![GitHub issues](https://img.shields.io/github/issues/GangGreenTemperTatum/csp-auditor)](https://github.com/GangGreenTemperTatum/csp-auditor/issues)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/GangGreenTemperTatum/csp-auditor)](https://github.com/GangGreenTemperTatum/csp-auditor/releases)
[![GitHub stars](https://img.shields.io/github/stars/GangGreenTemperTatum/csp-auditor?style=social)](https://github.com/GangGreenTemperTatum/csp-auditor/stargazers)
[![License](https://img.shields.io/github/license/GangGreenTemperTatum/csp-auditor?branch=main)](https://github.com/GangGreenTemperTatum/csp-auditor/blob/main/LICENSE)

[Report Bug](https://github.com/GangGreenTemperTatum/csp-auditor/issues) •
[Request Feature](https://github.com/GangGreenTemperTatum/csp-auditor/issues)

<!--![csp-auditor Panel](./public/images/csp-auditor-panel.png)-->
<!--*CSP Auditor*-->

<!--CSP Auditor is now available via the [Caido Plugin Library](https://caido.io/plugins)! 🥳 CSP Auditor was [submitted to the Caido Plugin Library](https://github.com/caido/store/pull/41) and is approved, it will be available for installation directly from the Caido plugin store page.-->

<!--![https://caido.io/plugins](./public/images/caido-plugin-store.png)-->

</div>

---

- [CSP Auditor](#csp-auditor)
  - [Overview](#overview)
  - [Features](#features)
  - [Development TODO](#development-todo)
    - [CSP Bypass Integration (COA)](#csp-bypass-integration-coa)
  - [Quick Start](#quick-start)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Install from source (without auto-updates):](#install-from-source-without-auto-updates)
    - [Usage](#usage)
      - [Dashboard \& Analysis](#dashboard--analysis)
      - [Vulnerability Detection](#vulnerability-detection)
      - [Bypass Database](#bypass-database)
      - [Configuration](#configuration)
  - [Contributing](#contributing)
    - [Adding New Bypass Gadgets](#adding-new-bypass-gadgets)
    - [General Development](#general-development)
  - [License](#license)
  - [Star History](#star-history)

## Overview

CSP Auditor is a Caido plugin that helps you monitor and analyze Content Security Policies (CSP) in web applications, it is designed to mimic the [Burp Suite extension](https://github.com/portswigger/csp-auditor)'s functionality with additional improvements and integration with [`cspbypass.com`](https://cspbypass.com) for a built-in bypass database of real-world CSP bypass techniques, directly in Caido!

![csp-auditor main panel](./assets/public/csp-auditor-main-panel.png)
<div align="center"><i>csp-auditor main panel</i></div>

## Features

- **Real-time CSP Analysis**: Automatically analyzes CSP headers from intercepted HTTP responses
- **34+ Vulnerability Checks**: Comprehensive detection of CSP misconfigurations including:
  - Script wildcard sources and unsafe directives
  - JSONP bypass risks and AngularJS template injection
  - AI/ML and Web3 service integration risks
  - Missing Trusted Types and essential directives
  - Deprecated headers and vulnerable library hosts
- **209+ Bypass Payloads**: Integrated database of real-world CSP bypass techniques from [CSPBypass research](./data/csp-bypass-data.tsv)
   > A thank you to Rennie Pak and contributors of the project for the original [CSP gadgets](https://cspbypass.com/) 🙏
- **Searchable Bypass Database**: Filter and copy bypass payloads directly from the plugin interface
- **Vulnerability Modals**: Detailed vulnerability information with relevant bypass examples and payload copying
- **Configurable Detection**: Enable/disable specific vulnerability checks via settings panel
- **Caido Findings Integration**: Automatically create findings for detected vulnerabilities
- **Scope Awareness**: Respect Caido's project scope settings for targeted analysis
- **Export Functionality**: Export findings as JSON or CSV for reporting
- **Dashboard Statistics**: Overview of analyzed policies, vulnerabilities by severity, and detection trends

<!-- Come [join](https://discord.com/invite/Xkafzujmuh) the **awesome** Caido discord channel and come speak to me about CSP Auditor in it's [dedicated channel](https://discord.com/channels/843915806748180492/1407063905511145653)! -->

---

## Development TODO

### CSP Bypass Integration (COA)
- [x] Phase 1: Enhanced vulnerability modal with bypass examples and payload copying
- [ ] Phase 2: Dedicated bypass testing tab with syntax highlighting
- [ ] Phase 3: Inline bypass indicators and real-time analysis

---

## Quick Start

### Prerequisites

- [Caido](https://caido.io) (latest version)
- Node.js and pnpm (for development)

### Installation

<!--
### Method 1 - Install directly in Caido (recommended):

1. Open Caido, navigate to the `Plugins` sidebar page and then to the `Community Store` tab
2. Find `csp-auditor` and click `Install`
3. Done! 🎉

### Method 2 - Install from source (without auto-updates):
-->

### Install from source (without auto-updates):

1. **Clone the repository:**
   ```bash
   git clone https://github.com/GangGreenTemperTatum/csp-auditor.git
   cd csp-auditor
   ```

2. **Install dependencies:**
   ```bash
   pnpm install
   ```

3. **Build the plugin:**
   ```bash
   pnpm build
   ```

4. **Install in Caido:**
   - Open Caido
   - Go to Settings > Plugins
   - Click "Install from file"
   - Select the built plugin file from the `dist/` directory

---

### Usage

CSP Auditor automatically monitors your HTTP traffic and analyzes CSP headers in real-time. Once installed, it works seamlessly in the background.

#### Dashboard & Analysis
- **View CSP Statistics**: Navigate to the CSP Auditor panel to see vulnerability counts by severity (high/medium/low/info)
- **Analyze Individual Responses**: Click on any analyzed response to view detailed CSP policy breakdown and specific vulnerabilities
- **Export Reports**: Export findings as JSON or CSV for documentation and reporting

![csp-auditor analysis clickable](./assets/public/csp-auditor-analysis-clickable.png)
<div align="center"><i>csp-auditor analysis clickable</i></div>

![csp-auditor analysis modal](./assets/public/csp-auditor-modal-1.png)
<div align="center"><i>csp-auditor analysis modal</i></div>

![csp-auditor analysis modal](./assets/public/csp-auditor-modal-2.png)
<div align="center"><i>csp-auditor analysis modal</i></div>

#### Vulnerability Detection
- **Real-time Alerts**: Automatic detection of 34+ CSP misconfigurations as you browse
- **Caido Findings**: Enable auto-creation of findings for detected vulnerabilities (toggle in settings)
- **Severity Classification**: Vulnerabilities categorized by impact level with detailed descriptions

![csp-auditor vulnerability finding](./assets/public/csp-auditor-finding.png)
<div align="center"><i>csp-auditor finding</i></div>

#### Bypass Database
- **209+ Real-world Bypasses**: Searchable database of CSP bypass techniques from security research
- **Copy Payloads**: One-click copying of bypass code for testing
- **Contextual Examples**: Relevant bypasses shown in vulnerability modals for immediate testing

![csp-auditor bypass gadget db](./assets/public/csp-auditor-bypass-gadget-db.png)
<div align="center"><i>csp-auditor bypass gadget db</i></div>

#### Configuration
- **Scope Awareness**: Respects Caido's project scope settings for targeted analysis
- **Customizable Checks**: Enable/disable specific vulnerability types via settings panel
- **Cache Management**: Clear analysis cache when needed

![csp-audit settings](./assets/public/csp-audit-settings.png)
<div align="center"><i>csp-audit settings</i></div>

---

## Contributing

### Adding New Bypass Gadgets

CSP Auditor uses a comprehensive database of bypass techniques sourced from security research. To add new bypass gadgets:

1. **Edit the TSV file**: Add new entries to `data/csp-bypass-data.tsv` in the following format:
   ```
   domain.example.com	<script src="https://domain.example.com/payload.js"></script>
   ```
   - **Column 1**: Domain or service name
   - **Column 2**: The actual bypass payload/code
   - Use TAB character as separator (not spaces)

2. **Technique Detection**: The plugin automatically categorizes bypasses by technique:
   - JSONP (contains `callback=` or `cb=`)
   - AngularJS (contains `ng-` or `angular`)
   - Alpine.js (contains `x-init` or `alpine`)
   - HTMX (contains `hx-`)
   - Hyperscript (contains `_="`)
   - Script Injection (contains `<script`)
   - Event Handler (contains `<img` and `onerror`)
   - Link Preload (contains `<link` and `onload`)
   - Iframe Injection (contains `<iframe`)
   - Generic XSS (fallback category)

3. **Testing**: After adding entries, rebuild the plugin with `pnpm build` and test that new bypasses appear in the searchable database panel.

### General Development

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=GangGreenTemperTatum/csp-auditor&type=Date)](https://star-history.com/#GangGreenTemperTatum/csp-auditor&Date)

Made with ❤️ for the Caido community by [@GangGreenTemperTatum](https://github.com/GangGreenTemperTatum)
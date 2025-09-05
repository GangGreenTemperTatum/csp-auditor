# CSP Auditor

<div align="center">

_A comprehensive Content Security Policy (CSP) vulnerability scanner plugin for Caido, designed to automatically detect and analyze CSP headers for common security misconfigurations and vulnerabilities._

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
  - [TODO](#todo)
  - [Quick Start](#quick-start)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Install from source (without auto-updates):](#install-from-source-without-auto-updates)
    - [Usage](#usage)
  - [Contributing](#contributing)
  - [License](#license)
  - [Star History](#star-history)


## Overview

🚧 **Note**: CSP Auditor is still in active development, not yet submitted to the Caido plugin store but will be done by September 2025.

CSP Auditor is a Caido plugin that helps you monitor and analyze Content Security Policies (CSP) in web applications, it is designed to mimic the [Burp Suite extension](https://github.com/portswigger/csp-auditor)'s functionality with additional improvements.

<!-- Come [join](https://discord.com/invite/Xkafzujmuh) the **awesome** Caido discord channel and come speak to me about CSP Auditor in it's [dedicated channel](https://discord.com/channels/843915806748180492/1407063905511145653)! -->

## TODO

- [ ] Fix copy icon not appearing as light mode
- [ ] Hook into [`csp-bypass.com`](https://csp-bypass.com) and also provide csp-auditor-like syntax highlighting and interface
- [ ] Include settings for aggressive, light scanning mode etc
- [ ] Create findings
- [ ] Add popup dialogues for "recent CSP analyses" individual findings to provide context and details
- [ ] Add images to docs and basic usage
- [ ] Add more CSP directives support and toggle certain CSP directives

## Quick Start

### Prerequisites

- Caido (latest version)
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

### Usage



<!--![csp-auditor Notification](./public/images/csp-auditor-popup-alert-1.png)
*csp-auditor notification*-->

<!--![csp-auditor Notification](./public/images/csp-auditor-popup-alert-2.png)-->
<!--*csp-auditor notification*-->

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=GangGreenTemperTatum/csp-auditor&type=Date)](https://star-history.com/#GangGreenTemperTatum/csp-auditor&Date)

Made with ❤️ for the Caido community by @GangGreenTemperTatum
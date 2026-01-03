# 📄 Pwnsheet - Dynamic Pentesting Cheatsheet

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple.svg)](https://getbootstrap.com)

> ⚠️ **Disclaimer**
>
> **Pwnsheet is for educational and authorized security testing only.**
> - Only use this tool on systems for which you have explicit permission to perform testing
> - Authors are not responsible for misuse  

## 🎯 What is Pwnsheet?

A smart, interactive cheatsheet designed to streamline penetration testing assessments. Pwnsheet transforms static markdown notes into a dynamic, browser-based workspace with intelligent parameter management and progress tracking.

![Pwnsheet Screenshot](assets/screenshot.png) 

## ✨ Key Features

Everything follows an interactive, dynamic approach—helpers react to your inputs and keep commands in sync.

- **📋 Phase-Based Workflow** - Cheatsheet for all pentesting phases from reconnaissance to lateral movement
- **🎯 Dynamic Parameters** - Click any code block to filter relevant parameters; auto-populate commands across the assessment
- **✅ Progress Tracking** - Interactive checkboxes with persistent state to track your assessment progress
- **📦 Zero Dependencies** - Pure HTML/CSS/JS with no build process; runs entirely in the browser
- **💾 Local Storage** - All progress and parameters saved locally; nothing leaves your machine
- **🎨 Modern UI** - Clean, responsive interface optimized for security professionals
- **🚚 File Transfer Helper** - Generates sender/receiver commands for faster file moves across hosts
- **🐚 Shells Helper** - Reverse shell oneliners, web shells, and stabilization commands on demand
- **🧰 Tools & Wordlists Table** - Quick download/install commands for common tools and wordlists
- **📝 Skeleton Notes Downloader** - Grab templated markdown notes to capture findings during assessments

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/0x8e5afe/pwnsheet.git
cd pwnsheet

# Start a local server
python3 -m http.server 8000

# Open in browser
# Navigate to http://localhost:8000
```

## 📖 How to Use

### 1. Select a Phase
Click any phase in the left panel to load its checklist and related cheatsheet.

### 2. Work with Parameters
Parameters appear in the right panel when present in a phase. They use the format `<PARAMETER_NAME>` or `{{PARAMETER_NAME}}`:

- **Global Mode** - Fill parameters to auto-populate throughout the entire phase
- **Code Block Mode** - Click any code block to filter only its relevant parameters
- **Search** - Use the search box to quickly find specific parameters

Example workflow:
```bash
# Phase contains: nmap -sV -p- <TARGET_IP>
# Enter 10.10.11.45 in TARGET_IP parameter
# Command auto-updates to: nmap -sV -p- 10.10.11.45
```

### 3. Track Progress
- Check off completed tasks as you go
- All checkbox states persist between sessions
- Use the Reset button to start a fresh assessment

### 4. Copy Commands
- Simply highlight the piece of code in a snippet to copy it

## 🏗️ Project Structure

```
pwnsheet/
├── index.html          # Main application shell
├── scripts             # Core functionality split by concern
│   ├── constants.js    # Shared state, regexes, templates
│   ├── utils.js        # Marked setup + style helpers
│   ├── copy.js         # Copy/selection feedback utilities
│   ├── modals.js       # Modal logic, generators, tables
│   ├── content.js      # Markdown rendering + parameter wiring
│   └── main.js         # Entry point + global event wiring
├── styles.css          # UI styling and theme
├── README.md           # This file
└── notes               # markdown notes
    ├── 01 - Reconnaissance & Enumeration.md
    ├── 02 - Vulnerability Research & Exploitation.md
    ├── 03 - Active Directory Exploitation.md
    ├── 04 - Post Exploitation & Privilege Escalation.md
    ├── 05 - Lateral Movement.md
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

#### Reporting Issues
- Check existing issues first to avoid duplicates
- Provide clear reproduction steps
- Include browser/OS information for UI bugs

#### Suggesting Enhancements
- Open an issue describing the feature
- Explain the use case and benefits
- Consider implementation complexity

#### Update Content
- Add new pentesting commands and techniques
- Improve existing phase documentation
- Share helpful oneliners and workflows

### Submitting Pull Requests

1. **Fork and Clone**
Go to the [pwnsheet repository](https://github.com/0x8e5afe/pwnsheet), click "Fork" in the top-right corner, then clone your fork locally:
```bash
# Replace YOUR_USERNAME with your GitHub username
git clone https://github.com/YOUR_USERNAME/pwnsheet.git
cd pwnsheet
```

2. **Configure Upstream Remote**
Add the original repository as upstream to keep your fork synchronized:
```bash
# Add upstream remote
git remote add upstream https://github.com/0x8e5afe/pwnsheet.git

# Verify configuration
git remote -v
```
Expected output:
```bash
origin    https://github.com/YOUR_USERNAME/pwnsheet.git (fetch)
origin    https://github.com/YOUR_USERNAME/pwnsheet.git (push)
upstream  https://github.com/0x8e5afe/pwnsheet.git (fetch)
upstream  https://github.com/0x8e5afe/pwnsheet.git (push)
```

3. **Create a Feature Branch**
Never work directly on the main branch. Instead, create a dedicated branch for your changes:
```bash
# Sync with upstream
git checkout main
git pull upstream main

# Create your feature branch
git checkout -b feature/your-feature-name
```

Branch naming examples:
- `feature/add-web-shells-section`
- `fix/parameter-highlighting-bug`
- `docs/improve-installation-guide`

4. **Test Locally**
Start a local server and verify everything works before making changes:

```bash
python3 -m http.server 8000
```

Open [http://localhost:8000](http://localhost:8000) in your browser and test across different browsers. Use private/incognito mode to ensure your changes aren't affected by cached files.

5. **Make Your Changes**
Based on what you're contributing:

**For adding/modifying pentesting content:**

- Edit markdown files in the `notes/` directory
- Follow the existing parameter format: `<PARAMETER_NAME>` or `{{PARAMETER_NAME}}`
- Keep commands practical and commonly used

**For improving functionality:**

- `scripts/constants.js` - Shared state or templates
- `scripts/utils.js` - Helper functions
- `scripts/modals.js` - Modal behaviors
- `scripts/content.js` - Markdown rendering
- `scripts/main.js` - Global event handlers

**For UI improvements:**

- `styles.css` - Styling and themes
- `index.html` - Structure adjustments

6. **Test Thoroughly**
Before committing, verify your changes work correctly:

- Test across different browsers (Chrome, Firefox, Safari)
- Verify parameter replacement functionality
- Check that progress tracking persists between sessions
- Ensure mobile responsiveness for UI changes

7. **Commit and Push**
Use clear, descriptive commit messages that explain what and why:

```bash
# Stage your changes
git add .

# Commit with a meaningful message
git commit -m "Add post-exploitation Windows commands section"

# Push to your fork
git push origin feature/your-feature-name
```

Good commit message examples:

- "Add reverse shell one-liners for Python and Ruby"
- "Fix parameter highlighting in nested code blocks"
- "Update README with macOS installation instructions"

8. **Create a Pull Request**
Navigate to your fork on GitHub where you'll see a prompt to create a pull request. Click "Compare & pull request" and fill in the description:

```markdown
## Description
Added a comprehensive web shells section to the Post Exploitation phase with:
- PHP web shells
- ASP.NET web shells
- JSP web shells
- Parameter support for target URL and file path

## Testing
- Verified all commands render correctly
- Tested parameter replacement functionality
- Checked mobile responsiveness

## Related Issue
Closes #123 (if applicable)
```

### Keeping Your Fork Updated

Before starting new work, sync your fork with the upstream repository:

```bash
# Switch to main branch
git checkout main

# Fetch and merge upstream changes
git fetch upstream
git merge upstream/main

# Push updates to your fork
git push origin main
```
### Best Practices

1. **One feature per branch** - Don't mix multiple unrelated changes
2. **Test before submitting** - Make sure everything works
3. **Follow existing code style** - Match the project's conventions
4. **Write clear commits** - Future contributors will thank you
5. **Be responsive** - Address any feedback on your PR promptly
6. **Start small** - Fix a typo or add a small feature first
### Content Guidelines
When adding or modifying assessment phases:
- Keep commands practical and commonly used
- Add brief explanations for complex techniques
- Use consistent parameter naming conventions
- Include relevant tool documentation links
- Maintain ethical hacking principles

## 📜 License

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

## ⚖️ Ethical Use

This tool is designed for **authorized security testing only**. Users must:
- Obtain proper authorization before testing any systems
- Comply with all applicable laws and regulations
- Respect scope limitations and rules of engagement
- Use knowledge responsibly and ethically

Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

---

<div align="center">

Made with ❤️ by [Giuseppe Toscano](https://gtoscano.me) and [Gabriele Mossino](https://www.linkedin.com/in/gabriele-mossino/)

[⭐ Star on GitHub](https://github.com/0x8e5afe/pwnsheet)

</div>

# TraceTheLink

TraceTheLink is a practical URL and redirect analysis tool for phishing triage, suspicious link investigation, and analyst-friendly reporting.

It is designed for security analysts who need a quick view of where a link goes, how it changes across redirects, and whether the observed behavior deserves escalation.

TraceTheLink keeps a simple Streamlit interface for interactive review and now also supports command-line usage for terminal workflows, batch triage, and report export.

## Features

- Single URL analysis
- Batch URL analysis from a text file
- Redirect chain tracing with per-hop status codes
- Final URL resolution
- Domain change tracking across redirect hops
- Basic page metadata extraction, including page title and meta description
- Static detection of meta refresh and simple JavaScript redirect patterns
- Analyst-focused suspicious indicators
- Simple risk level, reasoning, and recommended action
- Plain text, JSON, and Markdown reporting
- Report export to file
- Streamlit UI and CLI support

## Installation

```bash
git clone https://github.com/T4riiiiq/TraceTheLink.git
cd TraceTheLink
pip install -r requirements.txt
```

## Streamlit Usage

Run the interactive interface:

```bash
streamlit run app.py
```

The Streamlit mode remains the primary interactive workflow and now uses the same reusable analysis logic as the CLI.

## CLI Usage

Analyze a single URL:

```bash
python tracethelink.py --url "https://example.com"
```

Return JSON:

```bash
python tracethelink.py --url "https://example.com" --output json
```

Save a Markdown report:

```bash
python tracethelink.py --url "https://example.com" --output markdown --save report.md
```

Analyze multiple URLs from a file:

```bash
python tracethelink.py --file urls.txt --output json --save results.json
```

Tune timeout and redirect depth:

```bash
python tracethelink.py --url "https://example.com" --timeout 10 --max-redirects 8
```

## Input File Format

For batch mode, use one URL per line:

```text
https://example.com
https://example.org/path
bit.ly/example
```

Blank lines and lines starting with `#` are ignored.

## Output Coverage

For each analyzed URL, TraceTheLink reports:

- Original URL
- Redirect chain
- Final URL
- HTTP status codes
- Domain changes
- Page title and basic metadata when available
- Suspicious indicators
- Risk level
- Risk reasoning
- Recommended analyst action

## Example Output

### Plain Text

```text
Original URL: https://example.com
Final URL: https://example.com/
Final Status: 200 (OK - Final content delivered.)
Risk Level: LOW (0/100)
Page Title: Example Domain
Recommended Action: Document the redirect behavior and monitor only if the link appears in a suspicious campaign or unusual workflow.
```

### Markdown

```markdown
## https://example.com

- **Final URL:** `https://example.com/`
- **Final Status:** `200` (OK - Final content delivered.)
- **Risk Level:** `LOW` (0/100)
```

## Safety Model

TraceTheLink is intended for defensive analysis and phishing/link triage.

- Does not submit forms
- Does not download or execute files
- Uses controlled HTTP requests with timeout
- JavaScript detection is static pattern-based only unless explicitly implemented otherwise
- Private/internal targets are blocked by default unless explicitly allowed
- Intended for defensive analysis and phishing/link triage

## Use Cases

- Triage links from phishing emails
- Review redirect behavior in user-reported messages
- Document suspicious link behavior in case notes
- Produce lightweight reports for analysts or incident responders
- Batch review small sets of URLs during investigations

## Limitations

- Not a full threat intelligence platform
- Static HTTP analysis only
- JavaScript handling is pattern-based and does not execute browser code
- No sandboxing, file detonation, reputation feeds, or active crawling
- Some pages may behave differently in a browser than in raw HTTP requests
- Risk scoring is heuristic and should support analyst judgment, not replace it

## Roadmap

- CSV export
- Optional screenshot capture via browser automation
- Additional URL normalization and enrichment
- Safer analyst notes and tagging for exported reports
- Optional IOC extraction helpers

## Project Structure

```text
TraceTheLink/
├── app.py
├── tracethelink.py
├── core/
│   ├── __init__.py
│   ├── analyzer.py
│   └── reporting.py
├── pages/
│   └── analysis.py
└── requirements.txt
```

CSP Header Checker - Web Interface
A comprehensive web application for analyzing Content Security Policy (CSP) headers for misconfigurations and security vulnerabilities.
Features
✅ Web-based Interface - Beautiful, user-friendly UI for checking CSP headers  
✅ Real-time Analysis - Instant feedback on CSP configurations  
✅ Critical Issue Detection - Identifies unsafe-inline, unsafe-eval, overly permissive settings  
✅ Warnings & Recommendations - Gets alerts about best practices and deprecated directives  
✅ Example CSP Headers - Pre-loaded examples from permissive to strict configurations  
✅ Directive Parsing - Shows parsed CSP directives in an organized view  
✅ REST API - Backend API for programmatic CSP checking
Project Structure
```
CSP Evulator/
├── csp_checker.py       # Core CSP analysis engine
├── app.py               # Flask web server
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # Web interface
└── README.md            # This file
```
Installation
1. Install Dependencies
```bash
pip install -r requirements.txt
```
Or manually install Flask:
```bash
pip install Flask
```
2. Verify Python Files
Ensure you have both files in the same directory:
`csp_checker.py` - CSP analysis logic
`app.py` - Flask web server
`templates/index.html` - Web interface
Running the Application
Via Command Line (Windows PowerShell)
```bash
python app.py
```
You should see output like:
```
======================================================================
CSP HEADER CHECKER - WEB SERVER
======================================================================

Starting Flask server...
Open your browser and go to: http://localhost:5000

Press Ctrl+C to stop the server
======================================================================
```
Access the Web Interface
Open your web browser and navigate to:
```
http://localhost:5000
```
Usage
1. Input CSP Header
Paste your CSP header in the text area. For example:
```
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'
```
2. Click "Check CSP Header"
The application will analyze your header and display results including:
Critical Issues - Major security problems (unsafe-inline, unsafe-eval, etc.)
Warnings - Concerning configurations (deprecated directives, wildcards, etc.)
Recommendations - Best practices and missing directives
3. Review Results
The results panel shows:
Summary counters for critical issues, warnings, and recommendations
Parsed directives with their values
Detailed explanations of each issue
Actionable recommendations
4. Use Examples
Click any of the example buttons to load pre-configured CSP headers:
Permissive - ⚠️ Unsafe configuration (for reference)
Moderate - Balanced security and functionality
Strict - ✓ Recommended for maximum security
Report-Only - With CSP reporting enabled
Check Categories
Critical Issues (⚠️)
`unsafe-inline` in script-src or style-src
`unsafe-eval` allowing eval() execution
`default-src *` allowing any source
Other severe security misconfigurations
Warnings (⚠️)
Deprecated directives (child-src, referrer)
Overly permissive wildcards (*, https:, http:)
Unknown/invalid directives
Risky directive combinations
Recommendations (💡)
Missing important directives (default-src, script-src, style-src)
Best practice suggestions
Security hardening tips
API Endpoints
POST /api/check
Check a CSP header for misconfigurations.
Request:
```json
{
    "csp_header": "default-src 'self'; script-src 'self' 'unsafe-inline'"
}
```
Response:
```json
{
    "success": true,
    "csp_header": "...",
    "directives": {...},
    "issues": [...],
    "warnings": [...],
    "recommendations": [...],
    "summary": {
        "critical_count": 0,
        "warning_count": 1,
        "recommendation_count": 0
    }
}
```
GET /api/examples
Get pre-configured example CSP headers.
Response:
```json
{
    "permissive": "...",
    "moderate": "...",
    "strict": "...",
    "report_only": "..."
}
```
Examples of CSP Headers
Permissive (Not Recommended)
```
default-src *; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'
```
Moderate
```
default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:
```
Strict (Recommended)
```
default-src 'none'; script-src 'self' 'nonce-2726c7f26c'; style-src 'self' 'nonce-2726c7f26c'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```
Keyboard Shortcuts
Ctrl+Enter - Check CSP header while in the text area
Click Example Buttons - Load pre-configured headers
Troubleshooting
Port Already in Use
If port 5000 is already in use, modify `app.py`:
```python
app.run(debug=True, host='localhost', port=5001)  # Use 5001 instead
```
Template Not Found Error
Make sure the `templates` directory exists in the same location as `app.py` and contains `index.html`.
Connection Refused
Make sure the Flask server is running and accessible at `http://localhost:5000`
Terminal Usage
The original terminal-based checker is still available:
```bash
python csp_checker.py
```
This runs an interactive CLI version where you can input CSP headers directly in the terminal.
Security Notes
This tool is designed to identify common CSP misconfigurations
It should be used as a development/testing aid, not as a substitute for professional security audits
Always test CSP headers thoroughly before deploying to production
Consider using `Content-Security-Policy-Report-Only` header first to test without enforcing
License
Free to use and modify.
Common CSP Directives
Directive	Purpose
`default-src`	Fallback for other directives
`script-src`	Controls script execution
`style-src`	Controls stylesheet loading
`img-src`	Controls image loading
`connect-src`	Controls connections (fetch, XHR, etc.)
`font-src`	Controls font loading
`object-src`	Controls plugin execution
`frame-ancestors`	Controls iframe embedding
`form-action`	Controls form submission targets
`base-uri`	Restricts base URL
`report-uri`	CSP violation reporting endpoint
Resources
MDN: Content Security Policy
OWASP: Content Security Policy
CSP Documentation

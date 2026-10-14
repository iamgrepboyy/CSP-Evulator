#!/usr/bin/env python3
"""
CSP Header Misconfiguration Checker
Analyzes Content Security Policy headers for security issues and misconfigurations
"""

import re
from typing import Dict, List, Tuple

class CSPChecker:
    """Check for CSP header misconfigurations"""
    
    # Common CSP directives
    VALID_DIRECTIVES = {
        'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
        'connect-src', 'media-src', 'object-src', 'frame-src', 'worker-src',
        'manifest-src', 'form-action', 'frame-ancestors', 'base-uri',
        'plugin-types', 'sandbox', 'upgrade-insecure-requests',
        'block-all-mixed-content', 'require-sri-for', 'require-trusted-types-for',
        'trusted-types', 'report-uri', 'report-to', 'child-src', 'prefetch-src'
    }
    
    # Deprecated directives
    DEPRECATED_DIRECTIVES = {
        'child-src': 'Use frame-src for frames or worker-src for workers',
        'referrer': 'Use Referrer-Policy header instead',
    }
    
    # Critical issues
    CRITICAL_KEYWORDS = {
        'unsafe-inline': 'Allows inline scripts/styles - major security risk',
        'unsafe-eval': 'Allows eval() - security risk',
        'unsafe-hashes': 'Use hashes for specific inline elements instead',
    }
    
    def __init__(self, csp_header: str):
        """Initialize checker with CSP header"""
        self.csp_header = csp_header.strip()
        self.directives = self._parse_csp()
        self.issues = []
        self.warnings = []
        self.recommendations = []

    @staticmethod
    def _normalize_source(value: str) -> str:
        """Normalize CSP source values for comparisons while preserving display values."""
        return value.strip().strip("'\"")
    
    def _parse_csp(self) -> Dict[str, List[str]]:
        """Parse CSP header into directives and values"""
        directives = {}
        
        # Split by semicolon to get individual directives
        parts = self.csp_header.split(';')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            # Split directive name from values
            tokens = part.split()
            if tokens:
                directive = tokens[0].lower()
                values = [v.lower() for v in tokens[1:]]
                directives[directive] = values
        
        return directives
    
    def check_all(self) -> None:
        """Run all checks"""
        self._check_critical_keywords()
        self._check_deprecated_directives()
        self._check_invalid_directives()
        self._check_wildcards()
        self._check_missing_directives()
        self._check_syntax()
        self._check_overly_permissive()
        self._check_directive_combinations()
    
    def _check_critical_keywords(self) -> None:
        """Check for unsafe-inline, unsafe-eval, etc."""
        for directive, values in self.directives.items():
            normalized_values = [self._normalize_source(value) for value in values]
            for keyword, description in self.CRITICAL_KEYWORDS.items():
                if keyword in normalized_values:
                    self.issues.append({
                        'severity': 'CRITICAL',
                        'directive': directive,
                        'issue': f"'{keyword}' found",
                        'description': description,
                        'value': ' '.join(values)
                    })
    
    def _check_deprecated_directives(self) -> None:
        """Check for deprecated directives"""
        for directive in self.directives.keys():
            if directive in self.DEPRECATED_DIRECTIVES:
                self.warnings.append({
                    'severity': 'WARNING',
                    'directive': directive,
                    'issue': 'Deprecated directive',
                    'recommendation': self.DEPRECATED_DIRECTIVES[directive]
                })
    
    def _check_invalid_directives(self) -> None:
        """Check for invalid directive names"""
        for directive in self.directives.keys():
            if directive not in self.VALID_DIRECTIVES and directive not in self.DEPRECATED_DIRECTIVES:
                self.warnings.append({
                    'severity': 'WARNING',
                    'directive': directive,
                    'issue': 'Unknown directive',
                    'description': 'This directive may not be recognized by browsers'
                })
    
    def _check_wildcards(self) -> None:
        """Check for overly permissive wildcard usage"""
        for directive, values in self.directives.items():
            normalized_values = [self._normalize_source(value) for value in values]

            if '*' in normalized_values:
                self.warnings.append({
                    'severity': 'WARNING',
                    'directive': directive,
                    'issue': "Wildcard '*' allows any source",
                    'description': 'Too permissive - defeats CSP purpose for this directive',
                    'value': ' '.join(values)
                })
            
            # Check for scheme-only wildcards like https:
            for value in values:
                normalized_value = self._normalize_source(value)
                if normalized_value in ['http:', 'https:', 'data:', 'blob:']:
                    if normalized_value != 'data:' and normalized_value != 'blob:':  # data: and blob: are usually safe
                        self.warnings.append({
                            'severity': 'WARNING',
                            'directive': directive,
                            'issue': f"Scheme-only '{normalized_value}' allows any {normalized_value.replace(':', '')} source",
                            'value': ' '.join(values)
                        })
    
    def _check_missing_directives(self) -> None:
        """Check for recommended directives that are missing"""
        important_directives = {'default-src', 'script-src', 'style-src'}
        missing = important_directives - set(self.directives.keys())
        
        if missing:
            self.recommendations.append({
                'type': 'MISSING_DIRECTIVES',
                'directives': list(missing),
                'description': 'These directives should be defined for better security'
            })
    
    def _check_syntax(self) -> None:
        """Check for syntax errors"""
        if not self.csp_header:
            self.issues.append({
                'severity': 'ERROR',
                'issue': 'Empty CSP header',
                'description': 'CSP header is empty'
            })
    
    def _check_overly_permissive(self) -> None:
        """Check for overly permissive configurations"""
        for directive, values in self.directives.items():
            normalized_values = [self._normalize_source(value) for value in values]

            # default-src * is very dangerous
            if directive == 'default-src' and '*' in normalized_values:
                self.issues.append({
                    'severity': 'CRITICAL',
                    'directive': 'default-src',
                    'issue': "default-src set to '*'",
                    'description': 'Completely defeats CSP purpose',
                    'value': ' '.join(values)
                })
            
            # Check for self with unsafe keywords
            if 'self' in normalized_values:
                unsafe_keywords = [v for v in normalized_values if 'unsafe' in v]
                if unsafe_keywords:
                    self.warnings.append({
                        'severity': 'WARNING',
                        'directive': directive,
                        'issue': f"'self' combined with {unsafe_keywords}",
                        'description': 'Using unsafe keywords defeats CSP protection',
                        'value': ' '.join(values)
                    })
    
    def _check_directive_combinations(self) -> None:
        """Check for problematic directive combinations"""
        if 'default-src' in self.directives and 'script-src' not in self.directives:
            default_values = [
                self._normalize_source(value)
                for value in self.directives['default-src']
            ]
            
            if '*' in default_values:
                self.warnings.append({
                    'severity': 'WARNING',
                    'issue': 'default-src * without script-src override',
                    'description': 'Script sources fall back to default-src *'
                })
    
    def get_xss_payloads(self):
        """Generate safe XSS payload examples based on CSP directives."""
        script_src_values = self.directives.get('script-src', self.directives.get('default-src', []))
        normalized_sources = [self._normalize_source(value) for value in script_src_values]
        allows_inline = 'unsafe-inline' in normalized_sources
        allows_unsafe_eval = 'unsafe-eval' in normalized_sources
        allows_nonce_or_hash = any(value.startswith('nonce-') or value.startswith('sha') for value in normalized_sources)
        allows_data = 'data:' in normalized_sources
        allows_blob = 'blob:' in normalized_sources
        allows_any = '*' in normalized_sources or any(value in ['http:', 'https:'] for value in normalized_sources)
        remote_sources = [value for value in normalized_sources if value.startswith('http:') or value.startswith('https:') or value.startswith('*.') or value.endswith('*')]

        payloads = [
            {
                'payload': "<img src=x onerror=alert('XSS')>",
                'description': 'Inline event-handler payload. Tests inline JavaScript and event-handler blocking.',
                'note': 'Allowed when inline scripts are permitted by CSP (unsafe-inline, nonce, or hash).'
                    if allows_inline or allows_nonce_or_hash
                    else 'Likely blocked unless the policy explicitly permits inline scripting.',
                'confidence': 'High' if allows_inline or allows_nonce_or_hash else 'Low'
            },
            {
                'payload': "<script>alert('XSS')</script>",
                'description': 'Inline script payload. Tests whether inline script execution is allowed.',
                'note': 'Likely allowed because script-src contains unsafe-inline.'
                    if allows_inline
                    else 'May be allowed only with a valid nonce or hash in the page.'
                    if allows_nonce_or_hash
                    else 'Likely blocked by CSP unless inline scripts are explicitly permitted.',
                'confidence': 'High' if allows_inline else 'Medium' if allows_nonce_or_hash else 'Low'
            },
            {
                'payload': "<svg><script>alert('XSS')</script></svg>",
                'description': 'SVG script payload. Useful when SVG content is allowed but regular inline script is blocked.',
                'note': 'SVG script payload can bypass restrictions in some browser contexts.',
                'confidence': 'Medium'
            },
            {
                'payload': "javascript:alert('XSS')",
                'description': 'JavaScript URI payload. Tests URL protocol restrictions in href/src attributes.',
                'note': 'Useful for testing javascript: URI restrictions in link and image attributes.',
                'confidence': 'Low'
            },
            {
                'payload': "data:text/html,<script>alert('XSS')</script>",
                'description': 'Data URI payload. Tests whether data: protocol execution is permitted.',
                'note': 'Likely allowed because CSP includes data: in script-src or default-src.'
                    if allows_data
                    else 'Blocked unless the policy explicitly allows data: sources.',
                'confidence': 'High' if allows_data else 'Low'
            },
            {
                'payload': "<iframe srcdoc=\"<script>alert('XSS')</script>\"></iframe>",
                'description': 'srcdoc iframe payload. Tests whether embedded HTML injection is possible.',
                'note': 'May be relevant when frame or child sources allow embedded HTML content.',
                'confidence': 'Low'
            }
        ]

        if remote_sources:
            payloads.append({
                'payload': "<script src='https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js'></script>",
                'description': 'Remote script payload. Tests whether external script hosts are accepted.',
                'note': 'Relevant when CSP allows external https hosts or specific remote script sources.',
                'confidence': 'Medium'
            })

        if allows_blob:
            payloads.append({
                'payload': "blob:data:text/html,<script>alert('XSS')</script>",
                'description': 'Blob URI payload. Tests whether blob: protocol execution is allowed.',
                'note': 'Useful when blob: is explicitly allowed by the CSP.',
                'confidence': 'High'
            })

        if allows_unsafe_eval:
            payloads.append({
                'payload': "<script>new Function(\"alert('XSS')\")()</script>",
                'description': 'unsafe-eval payload. Tests whether eval-style execution is permitted.',
                'note': 'Likely relevant because script-src contains unsafe-eval.',
                'confidence': 'High'
            })

        return payloads
    
    def get_report(self) -> str:
        """Generate formatted report"""
        report = []
        report.append("\n" + "="*70)
        report.append("CSP HEADER ANALYSIS REPORT")
        report.append("="*70)
        report.append(f"\nCSP Header:\n{self.csp_header}\n")
        
        # Parsed directives
        report.append("PARSED DIRECTIVES:")
        report.append("-" * 70)
        if self.directives:
            for directive, values in sorted(self.directives.items()):
                report.append(f"  {directive}: {' '.join(values)}")
        else:
            report.append("  No directives found")
        
        # Critical Issues
        critical = [i for i in self.issues if i.get('severity') == 'CRITICAL']
        if critical:
            report.append("\n" + "⚠️  CRITICAL ISSUES:")
            report.append("-" * 70)
            for idx, issue in enumerate(critical, 1):
                report.append(f"\n  {idx}. {issue.get('directive', 'General')}: {issue['issue']}")
                report.append(f"     Description: {issue.get('description', 'N/A')}")
                if 'value' in issue:
                    report.append(f"     Value: {issue['value']}")
        
        # Warnings
        if self.warnings:
            report.append("\n⚠️  WARNINGS:")
            report.append("-" * 70)
            for idx, warning in enumerate(self.warnings, 1):
                report.append(f"\n  {idx}. {warning.get('directive', 'General')}: {warning['issue']}")
                report.append(f"     Description: {warning.get('description', warning.get('recommendation', 'N/A'))}")
                if 'value' in warning:
                    report.append(f"     Value: {warning['value']}")
        
        # Recommendations
        if self.recommendations:
            report.append("\n💡 RECOMMENDATIONS:")
            report.append("-" * 70)
            for rec in self.recommendations:
                if rec['type'] == 'MISSING_DIRECTIVES':
                    report.append(f"\n  Missing: {', '.join(rec['directives'])}")
                    report.append(f"  {rec['description']}")
        
        # Summary
        report.append("\n" + "="*70)
        report.append("SUMMARY:")
        report.append(f"  Critical Issues: {len(critical)}")
        report.append(f"  Warnings: {len(self.warnings)}")
        report.append(f"  Recommendations: {len(self.recommendations)}")
        
        if not critical and not self.warnings:
            report.append("\n✓ No critical issues found!")
        
        report.append("="*70 + "\n")
        
        return "\n".join(report)


def main():
    """Main function - interactive CSP checker"""
    print("\n" + "="*70)
    print("CSP HEADER MISCONFIGURATION CHECKER")
    print("="*70)
    print("\nThis tool analyzes Content Security Policy (CSP) headers")
    print("for security misconfigurations and best practice violations.\n")
    
    while True:
        print("Enter your CSP header (or 'quit' to exit):")
        print("(Can be multiline - press Enter twice when done)\n")
        
        lines = []
        while True:
            try:
                line = input()
                if line.lower() == 'quit':
                    print("\nExiting...")
                    return
                if line == '':
                    if lines:
                        break
                    continue
                lines.append(line)
            except EOFError:
                if lines:
                    break
                return
        
        csp_header = ' '.join(lines)
        
        if not csp_header.strip():
            print("\n❌ Error: CSP header cannot be empty!\n")
            continue
        
        # Check and report
        checker = CSPChecker(csp_header)
        checker.check_all()
        print(checker.get_report())
        
        # Ask if user wants to check another
        response = input("Check another CSP header? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("\nThank you for using CSP Header Checker!")
            break


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CSP Header Checker - Flask Web Server
Provides a web interface for CSP header analysis
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from csp_checker import CSPChecker

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_csp():
    """API endpoint to check CSP header"""
    try:
        data = request.get_json()
        csp_header = data.get('csp_header', '').strip()
        
        if not csp_header:
            return jsonify({
                'success': False,
                'error': 'CSP header cannot be empty'
            }), 400
        
        # Run checker
        checker = CSPChecker(csp_header)
        checker.check_all()
        
        # Prepare response
        response = {
            'success': True,
            'csp_header': csp_header,
            'directives': checker.directives,
            'issues': checker.issues,
            'warnings': checker.warnings,
            'recommendations': checker.recommendations,
            'payloads': checker.get_xss_payloads(),
            'summary': {
                'critical_count': len([i for i in checker.issues if i.get('severity') == 'CRITICAL']),
                'warning_count': len(checker.warnings),
                'recommendation_count': len(checker.recommendations)
            }
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/examples', methods=['GET'])
def get_examples():
    """Get example CSP headers"""
    examples = {
        'permissive': "default-src *; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'",
        'moderate': "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:",
        'strict': "default-src 'none'; script-src 'self' 'nonce-2726c7f26c'; style-src 'self' 'nonce-2726c7f26c'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        'report_only': "default-src 'self'; script-src 'self' https://trusted.cdn.com; report-uri https://example.com/csp-report"
    }
    return jsonify(examples), 200

@app.route('/csp-domains')
def csp_domains():
    """Serve the CSP domains reference page"""
    return render_template('domains.html')

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Run the Flask app
    print("\n" + "="*70)
    print("CSP HEADER CHECKER - WEB SERVER")
    print("="*70)
    print("\nStarting Flask server...")
    print("Open your browser and go to: http://localhost:5000")
    print("\nPress Ctrl+C to stop the server")
    print("="*70 + "\n")
    
    app.run(debug=True, host='localhost', port=5000)

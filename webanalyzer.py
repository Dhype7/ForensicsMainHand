from flask import Flask, render_template, request
from src.modules.web_analyzer_project.web_tools.tools import get_headers, resolve_domain, detect_xss, port_scan, discover_login_pages, brute_force_login, check_security_headers

app = Flask(__name__, template_folder="src/modules/web_analyzer_project/templates")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/headers', methods=['POST'])
def headers():
    url = request.form.get('url') or ''
    results = get_headers(url)
    return render_template('result.html', results=results, title='HTTP Headers')

    
@app.route('/resolve', methods=['POST'])
def resolve():
    domain = request.form.get('domain') or ''
    results = resolve_domain(domain)
    return render_template('result.html', results=results, title='IP Resolver')

@app.route('/xss', methods=['POST'])
def xss():
    url = request.form.get('url') or ''
    results = detect_xss(url)
    return render_template('result.html', results=results, title='XSS Scanner')

@app.route('/ports', methods=['POST'])
def ports():
    domain = request.form.get('domain') or ''
    results = port_scan(domain)
    return render_template('result.html', results=results, title='Port Scanner')

@app.route('/security_headers', methods=['POST'])
def security_headers():
    url = request.form.get('url') or ''
    results = check_security_headers(url)
    return render_template('result.html', results=results, title='Security Headers Check')

@app.route('/discover_login', methods=['POST'])
def discover_login():
    base_url = request.form.get('base_url')
    if not base_url:
        return render_template('result.html', results={"Error": "No base URL provided."}, title='Login Page Discovery')
    results = discover_login_pages(base_url)
    found_login = None
    for url, val in results.items():
        if 'Login form found' in val:
            found_login = url
            break
    return render_template('result.html', results=results, title='Login Page Discovery', found_login=found_login)

@app.route('/brute_force_login', methods=['POST'])
def brute_force_login_route():
    login_url = request.form.get('login_url')
    # Hardcode for demo.testfire.net
    username_field = 'uid'
    password_field = 'passw'
    usernames = request.form.get('usernames', '')
    passwords = request.form.get('passwords', '')
    # Handle file uploads
    username_list = [u.strip() for u in usernames.split(',') if u.strip()]
    password_list = [p.strip() for p in passwords.split(',') if p.strip()]
    if 'usernames_file' in request.files and request.files['usernames_file'].filename:
        file = request.files['usernames_file']
        file_content = file.read().decode('utf-8', errors='ignore')
        username_list += [line.strip() for line in file_content.splitlines() if line.strip()]
    if 'passwords_file' in request.files and request.files['passwords_file'].filename:
        file = request.files['passwords_file']
        file_content = file.read().decode('utf-8', errors='ignore')
        password_list += [line.strip() for line in file_content.splitlines() if line.strip()]
    if not login_url:
        return render_template('result.html', results={"Error": "Missing required login form fields."}, title='Brute Force Login')
    results = brute_force_login(login_url, username_field, password_field, username_list, password_list)
    return render_template('result.html', results=results, title='Brute Force Login')

if __name__ == '__main__':
    app.run(debug=True)

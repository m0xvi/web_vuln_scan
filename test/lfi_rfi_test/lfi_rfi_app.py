from flask import Flask, request, render_template_string
import requests
import os

app = Flask(__name__)


# LFI Vulnerable route
@app.route('/include')
def include_file():
    page = request.args.get('page', 'index.html')
    try:
        if not os.path.isfile(page):
            return f"File {page} not found"
        with open(page, 'r') as file:
            content = file.read()
        return render_template_string(content)
    except Exception as e:
        return str(e)


# RFI Vulnerable route
@app.route('/rfi')
def rfi():
    url = request.args.get('url')
    try:
        response = requests.get(url)
        return response.text
    except Exception as e:
        return str(e)


@app.route('/')
def index():
    return '''
    <h1>LFI/RFI Test Application</h1>
    <h2>Local File Inclusion (LFI)</h2>
    <p>Try accessing <a href="/include?page=etc/passwd">/include?page=etc/passwd</a></p>
    <p>Or try including sensitive files like <a href="/include?page=passwd">/include?page=passwd</a></p>

    <h2>Remote File Inclusion (RFI)</h2>
    <p>Try accessing <a href="/rfi?url=https://raw.githubusercontent.com/your-username/your-repo/main/rfi_test.txt">/rfi?url=https://raw.githubusercontent.com/your-username/your-repo/main/rfi_test.txt</a></p>
    '''


if __name__ == '__main__':
    app.run(debug=True, port=5003)

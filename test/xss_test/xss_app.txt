from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)

# Хранение комментариев в памяти
comments = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reflected')
def reflected():
    search_query = request.args.get('q', '')
    return render_template('search.html', query=search_query)

@app.route('/stored', methods=['GET', 'POST'])
def stored():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        comments.append(comment)
        return redirect(url_for('stored'))
    return render_template('stored.html', comments=comments)

@app.route('/dom')
def dom():
    return render_template('dom.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)

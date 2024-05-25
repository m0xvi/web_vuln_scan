from flask import Flask, request, jsonify

app = Flask(__name__)

# Пример базы данных пользователей
users = {
    1: {"name": "Alice", "email": "alice@example.com"},
    2: {"name": "Bob", "email": "bob@example.com"},
    3: {"name": "Charlie", "email": "charlie@example.com"}
}

# Маршрут для получения информации о пользователе
@app.route('/user', methods=['GET'])
def get_user():
    user_id = request.args.get('id')
    if user_id is None:
        return "User ID is required", 400
    try:
        user_id = int(user_id)
        user = users.get(user_id)
        if user:
            return jsonify(user)
        else:
            return "User not found", 404
    except ValueError:
        return "Invalid User ID", 400

@app.route('/')
def index():
    return '''
    <h1>IDOR Test Application</h1>
    <p>Try accessing user profiles by visiting URLs like <a href="/user?id=1">/user?id=1</a></p>
    <p>Or try changing the ID parameter to access other user profiles.</p>
    '''

if __name__ == '__main__':
    app.run(debug=True, port=5004)

from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Simple Flask Test - Working!"

@app.route('/test')
def test():
    return "Test route working!"

if __name__ == '__main__':
    print("Starting simple Flask test...")
    app.run(host='0.0.0.0', port=5001, debug=True)
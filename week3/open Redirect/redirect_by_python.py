from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/')
def page():
    next = request.values.get('next')
    if next:
        return redirect(next)
    else:
        return 'Hi'
    
    
    
if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
    
    
# curl -I "http://localhost/?next=https://google.com" # Open Redirect
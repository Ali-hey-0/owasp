from flask import Flask,request
from jinja2 import Environment


app = Flask(__name__)
jinja2 = Environment()



@app.route("/page")
def page():
    
    name = request.values.get("name")
    
    output = jinja2.from_string('Hello'+name+'!').render()
    return output

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=80)
    
    

# $ curl -g "http://192.168.1.105/page?name=ali_cyber" #Hello ali_cyber!
# $ curl -g "http://192.168.1.105/page?name={{7*7}}" #hello49 
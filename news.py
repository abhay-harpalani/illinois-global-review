from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index_handler():
	print("url", request.url)
	return render_template("index.html", title="Test Article")
	# return "Hello World!"

if __name__ == "__main__":
	app.run(debug=False)

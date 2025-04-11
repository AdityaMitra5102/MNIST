from flask import *
import json

app=Flask(__name__, static_url_path="")

adminfile='/etc/rad/admin.json'

@app.route("/")
def index():
	return render_template("admin.html")
	
@app.route("/getusers")
def getusers():
	fl=open(adminfile, 'r')
	adminlist=json.load(fl)
	fl.close()
	return jsonify(adminlist)
	
@app.route("/saveusers", methods=["POST"])
def saveusers():
	adminlist=json.loads(request.data.decode())
	print(adminlist)
	fl=open(adminfile, 'w')
	save1=(json.dumps(adminlist, indent=4))
	fl.write(save1)
	fl.close()
	return jsonify({'status':'success'})
	
if __name__=='__main__':
	app.run(host='0.0.0.0', debug=True)

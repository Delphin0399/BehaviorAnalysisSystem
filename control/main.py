import os, time
import uuid
import yaml
from flask import Flask, request, send_file, abort, render_template, make_response, url_for
from werkzeug.utils import secure_filename
import threading
import classify

app = Flask(__name__)
last_error = ""

VERBOSE = True
TIMEOUT_LIMIT = 3

nodes = {}
allnodes = []
node_ip = {}
nodesTimeout = {}
nodesAuth = {}
nodesCode = {} #0-dead; 1-idle; 2-ready; 3-getFile; 4-work;
nodesFileId = {}



clf = classify.load("clf.pickle")
free_nodes = []
queue = []
requests = []
status = {}
verdict = {}


app.config['UPLOAD_FOLDER'] = "./files"
app.config['REPORT_FOLDER'] = "./reports"


def load_nodes():
    with open('nodes.yaml') as f:
        tmp_nodes = yaml.safe_load(f)
    if len(tmp_nodes) != 0:
        for n in tmp_nodes:
            allnodes.append(n['name'])
            nodes[n['name']] = "dead"
            if n['ip'] == None:
                node_ip[n['name']] = "not_assigned"
            else:
                node_ip[n['name']] = n['ip']
            nodesTimeout[n['name']] = 0
            if n['auth'] == None:
                nodesAuth[n['name']] = uuid.uuid4().hex
            else:
                nodesAuth[n['name']] = n['auth']
            
            nodesCode[n['name']] =  0

def dump_nodes():
    to_yaml = []
    for n in allnodes:
        tmp = {}
        tmp['name'] = n
        tmp['ip'] = node_ip[n]
        tmp['auth'] = nodesAuth[n]
        to_yaml.append(tmp)

    with open('nodes.yaml', 'w') as f:
        yaml.dump(to_yaml, f)



@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')
    if request.method == 'POST':
        file = request.files['file']
        #filename = secure_filename(file.filename)
        filename = uuid.uuid4().hex
        queue.append(filename)
        requests.append(filename)
        status[filename] = "queued"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename + " был загружен" + """<p><a href="/">К Задачам</a></p>"""
    return '''bad request'''



@app.route('/report', methods=['POST'])
def report():
    if request.method == 'POST':
        file = request.files['file']
        gottenUuid = request.headers.get('uuid')
        print(gottenUuid)
        if status.get(gottenUuid) != None:
            status[gottenUuid] = "Got Report"
            filename = secure_filename(gottenUuid)
            file.save(os.path.join(app.config['REPORT_FOLDER'], filename +".report"))
            print(f"received {filename} report")
            nodesCode[request.headers["name"]] = "6"
            x = threading.Thread(target=run_check, args=(filename,))
            x.start()
            return "success"
    return '''reports'''

@app.route('/task', methods=['GET'])
def taskStatus():
    if request.method == 'GET':
        if request.args.get('report') != None:
            filename = secure_filename(request.args.get('report'))
            filename = "./reports/" + filename + ".report"
            with open(filename, "r") as f:
                return send_file(filename)
        id = request.args.get('id')
        if verdict.get(id) != None:
            nodesCode['m1'] = 1
            return verdict.get(id)
        
        return 'Not found'



@app.route('/', methods=['GET', 'POST'])
def index():
    print(queue)
    res = ""
    #for f in requests:
    #    res += f + "&emsp;" + status[f] + "<br>"
    return render_template('index.html',alltasks=requests, status=status)

@app.route('/nodes', methods=['GET'])
def nodes_list():
    if request.method == 'GET':
        id = request.args.get('id')
        if id != None:
            #print(id)
            if nodes.get(id) != None:
                if check_node(request):
                    if id == request.headers.get('name'):
                        nodesTimeout[id] = 0
                        if nodesCode[id] == 0:
                            nodesCode[id] = 1
                            nodes[id] = "idle"
                            return "0"
                        return f"{nodesCode.get(id)}"
                    else:
                        abort(403)
                else:
                    return f"{nodes.get(id)}"
            else:
                return "No such Node"
        else:
            return render_template('nodes.html',allnodes=allnodes, nodesAuth=nodesAuth, nodes=nodes, node_ip=node_ip)
    else:
        abort(400)
        
@app.route('/work', methods=['GET'])
def work():
    if request.method == 'GET':
        if check_node(request):
            name = request.headers.get('name')
            if request.args.get('action') == 'get_id':
                return nodesFileId[name]
            else:
                nodesCode[name] = 4
                #status[nodesFileId[name]] = "in progress"
                response = make_response(send_file(os.path.join(app.config['UPLOAD_FOLDER'], nodesFileId[name]), as_attachment=True))
                return response
        else:
            abort(403)
    else:
        abort(400)

        
@app.route('/ready', methods=['GET'])
def ready():
    if request.method == 'GET':
        if check_node(request):
            name = request.headers.get('name')
            if name not in free_nodes:
                if nodesCode[name] == 1:
                    free_nodes.append(name)
                    nodes[name] = "ready"
                    nodesCode[name] = 2
                    if VERBOSE: print(f"{name} is ready")
                    return "ok"
                else: 
                    if VERBOSE: print(f"{name} not in state 1")
                    return "node is not ready"
            else:
                if VERBOSE: print(f"{name} is already in pool")
                return "false"
        else:
            abort(403)
    else:
        return "false"


def moveQueue():
    if len(queue) != 0:
        for f in queue:
            if len(free_nodes) != 0:
                workNode = free_nodes[0]
                free_nodes.remove(workNode)
                obj = queue[0]
                queue.remove(obj)
                #nodes[workNode] = "In Progress"
                #x = threading.Thread(target=start_detect, args=(obj,workNode,))
                nodesFileId[workNode] = obj
                nodesCode[workNode] = 3
                nodes[workNode] = "working"
                status[obj] = "in progress"
                print(f"Started {obj} job")
            else:
                if VERBOSE: print("No free sandbox node")
    else:
        if VERBOSE: print("No items in queue")
        
def run_check(id):
    #result = verdict(id)
    status[id] = "Complete"
    print("Checked report")
    X = classify.LoadValues(f"./files/{id}.report")
    verdict[id] = classify.predict(X, clf)
    

def check_node(req):
    
    auth = req.headers.get('auth')
    name = req.headers.get('name')
    
    if auth != None and name != None:
        if nodes.get(name) != None:
            if nodesAuth.get(name) == auth:
                last_error = "Wrong auth key"
                return True
        else:
            last_error = "No such node"
            return False
    else:
        last_error = "Wrong Headers"
        return False

def timer(timeInSec):
    while True:
        time.sleep(timeInSec)
        moveQueue()
        for n in allnodes:
            nodesTimeout[n] += 1
            if nodesTimeout[n] > TIMEOUT_LIMIT:
                declareDead(n)

def declareDead(n):
    
    nodes[n] = "dead"
    if n in free_nodes:
        free_nodes.remove(n)
    print(f"{n} is declared dead")
    if nodesCode[n] == 4 or nodesCode[n] == 4:
        print("File corrupted node. Rescan is advised")

    nodesCode[n] = 0

if __name__ == "__main__":
    load_nodes()
    dump_nodes()
    x = threading.Thread(target=timer, args=(10,))
    x.start()
    app.run(host = "0.0.0.0", port = 5000 ,debug = False)


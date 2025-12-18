from flask import Flask, request, jsonify, send_from_directory
from logic import ProcessTreeLogic
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logic = ProcessTreeLogic()

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/api/process-tree', methods=['GET'])
def get_process_tree():
    try:
        agent_id = request.args.get('agent_id')
        search = request.args.get('filter', "")
        time_range = request.args.get('range', "24")
        
        if not agent_id: return jsonify({"nodes": [], "edges": [], "stats": {"total": 0}}), 400
        
        events = logic.fetch_events(agent_id, hours_back=time_range)
        result = logic.build_tree(events, search)
        return jsonify(result)
    except Exception as e:
        logging.error(f"Erro na API: {e}")
        return jsonify({"error": str(e)}), 500

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

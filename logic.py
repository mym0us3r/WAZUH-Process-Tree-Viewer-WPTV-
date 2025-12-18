import json
import os
import logging
from datetime import datetime, timedelta, timezone
import dateutil.parser

class ProcessTreeLogic:
    def __init__(self):
        self.log_path = "/var/ossec/logs/alerts/alerts.json"

    def fetch_events(self, agent_id, hours_back=24):
        events = []
        if not os.path.exists(self.log_path): return []
        
        now_utc = datetime.now(timezone.utc)
        time_limit = now_utc - timedelta(hours=float(hours_back))
        
        try:
            # Abrindo com 'utf-8' mas ignorando erros de caracteres especiais (errors='replace')
            with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if f'"id":"{agent_id}"' in line and '4688' in line:
                        try:
                            item = json.loads(line)
                            ts_str = item.get('timestamp')
                            if not ts_str: continue
                            
                            event_time = dateutil.parser.isoparse(ts_str)
                            
                            if event_time.tzinfo is None:
                                event_time = event_time.replace(tzinfo=timezone.utc)
                            
                            if event_time >= time_limit:
                                events.append(item)
                        except: continue
            return events
        except Exception as e:
            logging.error(f"Erro ao filtrar logs: {e}")
            return []

    def hex_to_dec(self, hex_val):
        if not hex_val: return None
        try: return str(int(str(hex_val), 16))
        except: return str(hex_val)

    def build_tree(self, events, search_filter=""):
        nodes_map, edges, latest = {}, [], {}
        search_filter = search_filter.lower()
        
        known_pids = {}
        for item in events:
            ev = item.get('data', {}).get('win', {}).get('eventdata', {})
            pid = self.hex_to_dec(ev.get('newProcessId'))
            if pid:
                known_pids[pid] = os.path.basename(ev.get('newProcessName', 'Unknown'))

        for item in events:
            data_win = item.get('data', {}).get('win', {})
            ev = data_win.get('eventdata', {})
            sys = data_win.get('system', {})
            rule = item.get('rule', {})
            
            pid = self.hex_to_dec(ev.get('newProcessId'))
            ppid = self.hex_to_dec(ev.get('processId'))
            if not pid: continue
            
            full_path = ev.get('newProcessName', 'Unknown')
            if search_filter and search_filter not in full_path.lower(): continue

            ir_metadata = {
                'subjectUser': ev.get('subjectUserName', 'N/A'),
                'targetUser': ev.get('targetUserName', 'N/A'),
                'computer': sys.get('computer', 'N/A'),
                'eventId': sys.get('eventID', 'N/A'),
                'systemTime': sys.get('systemTime', 'N/A'),
                'ruleId': rule.get('id', 'N/A')
            }

            name = os.path.basename(full_path)
            parent_path = ev.get('parentProcessName', 'Unknown')
            parent_name = os.path.basename(parent_path) if 'Unknown' not in parent_path else known_pids.get(ppid, 'System/Service')
            cmd_line = ev.get('commandLine', 'N/A')

            if pid not in latest or item.get('timestamp') > latest[pid]['ts']:
                latest[pid] = {
                    'ts': item.get('timestamp'), 'name': name, 'ppid': ppid, 
                    'parent_name': parent_name, 'full_path': full_path, 
                    'cmd': cmd_line, 'ir': ir_metadata
                }

        for pid, d in latest.items():
            n_id = f"P{pid}"
            tooltip = (f"CMD: {d['cmd']}\n"
                       f"--------------------------\n"
                       f"USER: {d['ir']['subjectUser']} | HOST: {d['ir']['computer']}\n"
                       f"TIME: {d['ir']['systemTime']}\n"
                       f"RULE ID: {d['ir']['ruleId']}")

            nodes_map[n_id] = {
                'id': n_id, 'label': f"{d['name']}\n({pid})", 'title': tooltip,
                'color': { 'background': '#00a0d1', 'border': '#0077b5' }, 'font': { 'color': '#ffffff' }
            }
            
            if d['ppid'] and d['ppid'] != '0':
                p_id = f"P{d['ppid']}"
                if p_id not in nodes_map:
                    nodes_map[p_id] = {
                        'id': p_id, 'label': f"{d['parent_name']}\n({d['ppid']})", 
                        'color': { 'background': '#2d3748', 'border': '#ffffff' }, 
                        'font': { 'color': '#ffffff', 'size': 16 }, 'title': "Processo Pai"
                    }
                edges.append({'from': p_id, 'to': n_id})

        return {
            'nodes': list(nodes_map.values()), 'edges': edges,
            'stats': { 'total': len(latest), 'last_update': datetime.now().strftime("%H:%M:%S") }
        }

from flask import Flask, request, Response, jsonify
from prometheus_client import Counter, Summary, generate_latest, CONTENT_TYPE_LATEST, Gauge, Histogram, Info
import random
import time
from datetime import datetime

app = Flask(__name__)

CLIENT_DATABASES = Gauge('client_databases_total', 'Total client databases', ['status'])
COMPLIANCE_SCORE = Gauge('compliance_score', 'Compliance percentage')
SYSTEM_HEALTH = Gauge('system_health', 'System health status', ['component'])
DLP_STATUS = Info('dlp_status', 'DLP service status')
EVENTS_TOTAL = Counter('events_total', 'Total events', ['type', 'severity'])

REQUEST_COUNT = Counter('flask_request_count', 'Total requests', ['method', 'endpoint'])
EXCEPTIONS = Counter('flask_exceptions_total', 'Total exceptions', ['endpoint', 'exception_type'])
PRINT_NUMBER = Histogram('print_number_value', 'Numbers printed')

@app.errorhandler(Exception)
def catch_all(e):
    try:
        EXCEPTIONS.labels(endpoint=request.path, exception_type=type(e).__name__).inc()
        return jsonify({"error": str(e)}), 500
    except:
        return "Internal Server Error", 500

@app.before_request
def count_requests():
    try:
        REQUEST_COUNT.labels(method=request.method, endpoint=request.path).inc()
    except:
        pass  # Don't let metrics recording break the app

@app.route('/simulate_data')
def simulate_data():
    """Simulate dashboard data for demonstration"""
    
    CLIENT_DATABASES.labels(status='active').set(15)
    CLIENT_DATABASES.labels(status='inactive').set(3)
    CLIENT_DATABASES.labels(status='maintenance').set(2)
    
    compliance = random.randint(70, 95)
    COMPLIANCE_SCORE.set(compliance)
    
    SYSTEM_HEALTH.labels(component='database').set(random.choice([0, 1]))  
    SYSTEM_HEALTH.labels(component='api').set(random.choice([0, 1]))
    SYSTEM_HEALTH.labels(component='storage').set(random.choice([0, 1]))
    SYSTEM_HEALTH.labels(component='network').set(random.choice([0, 1]))
    
    DLP_STATUS.info({
        'status': 'running',
        'last_scan': datetime.now().isoformat(),
        'files_scanned': str(random.randint(1000, 5000))
    })
    
    EVENTS_TOTAL.labels(type='login', severity='info').inc(random.randint(1, 5))
    EVENTS_TOTAL.labels(type='download', severity='warning').inc(random.randint(0, 2))
    EVENTS_TOTAL.labels(type='access_denied', severity='critical').inc(random.randint(0, 1))
    
    return jsonify({
        'message': 'Data simulated successfully',
        'timestamp': datetime.now().isoformat(),
        'compliance_score': compliance
    })

@app.route('/dashboard_data')
def dashboard_data():
    """Return dashboard data in JSON format"""
    return jsonify({
        'client_databases': [
            {'name': 'TechCorp', 'status': 'Active', 'last_backup': '2024-02-04', 'compliance': 'Secure and Safe'},
            {'name': 'MedCorp', 'status': 'Active', 'last_backup': '2024-02-03', 'compliance': 'Warning'},
            {'name': 'FinCorp', 'status': 'Inactive', 'last_backup': '2024-01-28', 'compliance': 'Critical'}
        ],
        'events': [
            {'timestamp': '2024-02-04 14:23', 'user_id': 12, 'action': 'LOGIN', 'details': 'Successful Login', 'ip': '192.168.1.1'},
            {'timestamp': '2024-02-04 14:21', 'user_id': 5, 'action': 'DOWNLOAD FILE', 'details': 'Downloaded File', 'ip': '192.168.1.100'},
            {'timestamp': '2024-02-04 14:20', 'user_id': 8, 'action': 'ACCESS DENIED', 'details': 'Virus Attempt Denied', 'ip': '192.168.1.5'}
        ],
        'system_status': {
            'overall': 'Healthy',
            'dlp_status': 'Currently Running',
            'last_scan': '2-14-2024 9:34:43'
        }
    })

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.route('/')
def index():
    return """
    <h1>SentinelSupport Dashboard Service</h1>
    <ul>
        <li><a href="/simulate_data">Simulate Dashboard Data</a></li>
        <li><a href="/dashboard_data">View Dashboard Data (JSON)</a></li>
        <li><a href="/metrics">Prometheus Metrics</a></li>
    </ul>
    """

if __name__ == '__main__':
    try:
        # Initialize some metrics
        CLIENT_DATABASES.labels(status='active').set(15)
        CLIENT_DATABASES.labels(status='inactive').set(3)
        COMPLIANCE_SCORE.set(76)
        
        print("Starting Flask app on 0.0.0.0:5000")
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(f"Failed to start Flask app: {e}")
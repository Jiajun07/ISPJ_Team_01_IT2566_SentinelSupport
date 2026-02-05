from flask import Flask, request, Response, jsonify
from prometheus_client import Counter, Summary, generate_latest, CONTENT_TYPE_LATEST, Gauge, Histogram, Info
import random
import time
from datetime import datetime, timedelta
from AuditService.LogService import SysLogService
from database import MasterSessionLocal
from sqlalchemy import text

app = Flask(__name__)

CLIENT_DATABASES = Gauge('client_databases_total', 'Total client databases', ['status'])
COMPLIANCE_SCORE = Gauge('compliance_score', 'Compliance percentage')
SYSTEM_HEALTH = Gauge('system_health', 'System health status', ['component'])
DLP_STATUS = Info('dlp_status', 'DLP service status')
EVENTS_TOTAL = Counter('events_total', 'Total events', ['type', 'severity'])

REQUEST_COUNT = Counter('flask_request_count', 'Total requests', ['method', 'endpoint'])
EXCEPTIONS = Counter('flask_exceptions_total', 'Total exceptions', ['endpoint', 'exception_type'])
PRINT_NUMBER = Histogram('print_number_value', 'Numbers printed')

def update_real_metrics():
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        with MasterSessionLocal() as session:
            query = text("""
                SELECT 
                    COUNT(CASE WHEN action_type LIKE '%LOGIN%' AND success = true THEN 1 END) as successful_logins,
                    COUNT(CASE WHEN action_type LIKE '%LOGIN%' AND success = false THEN 1 END) as failed_logins,
                    COUNT(CASE WHEN action_type LIKE '%UPLOAD%' THEN 1 END) as file_uploads,
                    COUNT(CASE WHEN action_type LIKE '%DOWNLOAD%' THEN 1 END) as file_downloads,
                    COUNT(CASE WHEN action_type LIKE '%DLP%' THEN 1 END) as dlp_scans,
                    COUNT(CASE WHEN action_category = 'SECURITY' THEN 1 END) as security_events,
                    COUNT(CASE WHEN success = false THEN 1 END) as failed_operations,
                    COUNT(DISTINCT target_tenant_id) as active_tenants,
                    COUNT(*) as total_events
                FROM system_audit_logs 
                WHERE created_at >= :start_date AND created_at <= :end_date
            """)
            
            result = session.execute(query, {
                'start_date': start_date,
                'end_date': end_date
            }).fetchone()
            
            if result:
                EVENTS_TOTAL.labels(type='login_success', severity='info')._value._value = result.successful_logins
                EVENTS_TOTAL.labels(type='login_failed', severity='warning')._value._value = result.failed_logins
                EVENTS_TOTAL.labels(type='file_upload', severity='info')._value._value = result.file_uploads
                EVENTS_TOTAL.labels(type='file_download', severity='info')._value._value = result.file_downloads
                EVENTS_TOTAL.labels(type='dlp_scan', severity='info')._value._value = result.dlp_scans
                EVENTS_TOTAL.labels(type='security_event', severity='warning')._value._value = result.security_events
                
                CLIENT_DATABASES.labels(status='active').set(result.active_tenants)
                
                success_rate = ((result.total_events - result.failed_operations) / result.total_events * 100) if result.total_events > 0 else 100
                COMPLIANCE_SCORE.set(success_rate)
                
                print(f"Updated metrics: {result.total_events} events, {success_rate:.1f}% compliance")
                
    except Exception as e:
        print(f"Error updating real metrics: {e}")

@app.route('/metrics')
def metrics():
    update_real_metrics()
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.route('/dashboard_data')
def dashboard_data():
        with MasterSessionLocal() as session:
            recent_events_query = text("""
                SELECT 
                    created_at,
                    admin_email,
                    action_type,
                    action_description,
                    ip_address,
                    success,
                    target_tenant_id
                FROM system_audit_logs 
                ORDER BY created_at DESC 
                LIMIT 10
            """)
            
            events_result = session.execute(recent_events_query)
            
            real_events = []
            for event in events_result:
                real_events.append({
                    'timestamp': event.created_at.strftime('%Y-%m-%d %H:%M') if event.created_at else 'Unknown',
                    'user_id': event.admin_email or 'System',
                    'action': event.action_type or 'UNKNOWN_ACTION',
                    'details': event.action_description or 'No description',
                    'ip': event.ip_address or 'Unknown IP',
                    'success': event.success,
                    'tenant': event.target_tenant_id or 'System'
                })
            
            tenant_query = text("""
                SELECT 
                    target_tenant_id,
                    COUNT(*) as activity_count,
                    MAX(created_at) as last_activity,
                    ROUND(AVG(CASE WHEN success THEN 100.0 ELSE 0.0 END), 1) as success_rate
                FROM system_audit_logs 
                WHERE created_at >= NOW() - INTERVAL '7 days'
                AND target_tenant_id IS NOT NULL
                GROUP BY target_tenant_id
                ORDER BY activity_count DESC
            """)
            
            tenant_result = session.execute(tenant_query)
            
            client_databases = []
            for tenant in tenant_result:
                status = 'Active' if tenant.success_rate > 90 else 'Warning' if tenant.success_rate > 70 else 'Critical'
                compliance = 'Secure and Safe' if tenant.success_rate > 90 else 'Warning' if tenant.success_rate > 70 else 'Critical'
                
                client_databases.append({
                    'name': f'Tenant {tenant.target_tenant_id}',
                    'status': status,
                    'last_backup': tenant.last_activity.strftime('%Y-%m-%d') if tenant.last_activity else 'Never',
                    'compliance': f'{compliance} ({tenant.success_rate}%)',
                    'activity_count': tenant.activity_count
                })
            system_query = text("""
                SELECT 
                    COUNT(*) as total_today,
                    COUNT(CASE WHEN success = false THEN 1 END) as failures_today
                FROM system_audit_logs 
                WHERE DATE(created_at) = CURRENT_DATE
            """)

            system_result = session.execute(system_query).fetchone()
        
            overall_status = 'Healthy'
            if system_result:
                failure_rate = (system_result.failures_today / system_result.total_today * 100) if system_result.total_today > 0 else 0
                if failure_rate > 20:
                    overall_status = 'Critical'
                elif failure_rate > 10:
                    overall_status = 'Warning'
            
            
            return jsonify({
            'client_databases': client_databases,
            'events': real_events,
            'system_status': {
                'overall': overall_status,
                'dlp_status': 'Active' if any('DLP' in e['action'] for e in real_events) else 'Idle',
                'last_scan': datetime.now().strftime('%m-%d-%Y %H:%M:%S'),
                'total_events_today': system_result.total_today if system_result else 0
            }
        })
    
    
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
import os
import json
import csv
from datetime import datetime, timedelta
import tempfile
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from database import MasterSessionLocal
from AuditService.LogService import SysLogService
from io import StringIO
from flask import Response
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

class ComplianceService:
    @staticmethod
    def generateComplianceData(tenantID=None, startDate=None, endDate=None):
        if not startDate:
            startDate = datetime.now() - timedelta(days=30)
        if not endDate:
            endDate = datetime.now()
        
        try:
            with MasterSessionLocal() as session:
                base_query = """
                    SELECT 
                        id, created_at, target_tenant_id, admin_id, admin_email,
                        action_type, target_resource, resource_id, success,
                        action_description, action_category, ip_address,
                        user_agent, before_state, after_state, additional_data
                    FROM system_audit_logs
                    WHERE created_at BETWEEN :start_date AND :end_date
                """
                
                params = {
                    "start_date": startDate,
                    "end_date": endDate 
                }

                if tenantID:
                    base_query += " AND target_tenant_id = :tenant_id"
                    params["tenant_id"] = str(tenantID)
                
                base_query += " ORDER BY created_at DESC"
                
                print(f" Executing query with params: {params}")
                result = session.execute(text(base_query), params)
                logs = result.fetchall()
                
                print(f" Found {len(logs)} audit log entries")
                
                logData = []
                for log in logs:
                    additional_data = {}
                    if log.additional_data:
                        try:
                            additional_data = json.loads(log.additional_data)
                        except:
                            additional_data = {}
                    
                    logData.append({
                        'id': log.id,
                        'timestamp': log.created_at,
                        'tenant_id': log.target_tenant_id,
                        'actor_id': log.admin_id,
                        'actor_email': log.admin_email or 'System',
                        'actor_role': ComplianceService.determine_actor_role(log.action_type, log.target_tenant_id),
                        'action': log.action_type,
                        'resource_type': log.target_resource or 'SYSTEM',
                        'resource_id': log.resource_id,
                        'result': 'SUCCESS' if log.success else 'FAILURE',
                        'severity': ComplianceService.determine_severity(log.action_type, log.success),
                        'details': log.action_description or '',
                        'category': log.action_category or 'SYSTEM',
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent,
                        'before_state': log.before_state,
                        'after_state': log.after_state,
                        'additional_data': additional_data
                    })
                
                summary = ComplianceService.calculateSummary(logData)
                
                print(f" Generated compliance report: {summary['total_events']} events, {summary['success_rate']}% success rate")
                
                return logData, summary
                    
        except Exception as e:
            print(f" Error generating compliance data: {e}")
            import traceback
            traceback.print_exc()
            return [], {}

    @staticmethod
    def determine_actor_role(action_type, tenant_id):
        if tenant_id == 'SYSTEM' or action_type.startswith('SYSTEM_'):
            return 'SYSTEM_ADMIN'
        elif action_type.startswith('TENANT_ADMIN'):
            return 'TENANT_ADMIN'
        elif action_type.startswith('TENANT_'):
            return 'TENANT_USER'
        else:
            return 'SYSTEM'

    @staticmethod
    def calculateSummary(logs):
        if not logs:
            return {
                'total_events': 0,
                'successful_logins': 0,
                'failed_logins': 0,
                'file_uploads': 0,
                'file_deletions': 0,
                'file_shares': 0,
                'dlp_violations': 0,
                'dlp_scans_total': 0,
                'admin_actions': 0,
                'security_events': 0,
                'tenant_management': 0,
                'config_changes': 0,
                'database_operations': 0,
                'system_operations': 0,
                'unique_tenants': 0,
                'unique_users': 0,
                'success_rate': 100.0,
                'high_risk_events': 0,
                'compliance_dashboard_access': 0,
                'audit_log_access': 0,
                'data_exports': 0,
                'file_downloads': 0,
                'share_links_created': 0,
                'key_exchanges': 0,
                'retention_cleanups': 0,
                'failed_2fa_attempts': 0
            }
        
        summary = {
            'total_events': len(logs),

            'successful_logins': ComplianceService.count_action(logs, [
                'TENANT_USER_LOGIN', 'SYSTEM_ADMIN_LOGIN', 'TENANT_ADMIN_LOGIN'
            ], success=True),
            'failed_logins': ComplianceService.count_action(logs, [
                'TENANT_USER_LOGIN', 'SYSTEM_ADMIN_LOGIN', 'TENANT_ADMIN_LOGIN'
            ], success=False),
            'failed_2fa_attempts': ComplianceService.count_action(logs, [
                'TWO_FACTOR_AUTH_FAILED'
            ]),
            
            'file_uploads': ComplianceService.count_action(logs, [
                'TENANT_FILE_UPLOAD', 'FILE_UPLOADED', 'FILE_UPLOAD_TEMP'
            ]),
            'file_downloads': ComplianceService.count_action(logs, [
                'FILE_DOWNLOADED', 'TENANT_FILE_DOWNLOAD'
            ]),
            'file_deletions': ComplianceService.count_action(logs, [
                'TENANT_FILE_DELETE', 'FILE_DELETED', 'FILE_MOVED_TO_BIN'
            ]),
            'file_shares': ComplianceService.count_action(logs, [
                'TENANT_FILE_SHARE', 'SHARE_LINK_GENERATED', 'FILE_SHARED'
            ]),
            'share_links_created': ComplianceService.count_action(logs, [
                'SHARE_LINK_GENERATED'
            ]),
            'key_exchanges': ComplianceService.count_action(logs, [
                'KEY_EXCHANGE_INITIATED', 'KEY_EXCHANGE_COMPLETED'
            ]),
            
            'dlp_scans_total': ComplianceService.count_action(logs, [
                'TENANT_DLP_SCAN', 'DLP_SCAN_COMPLETED'
            ]),
            'dlp_violations': ComplianceService.count_action(logs, [
                'TENANT_DLP_SCAN', 'DLP_SCAN_COMPLETED'
            ], success=False),
            
            'admin_actions': ComplianceService.count_action(logs, [
                'TENANT_ADMIN_CREATE', 'TENANT_ADMIN_DELETE', 'TENANT_ADMIN_RESET_PASSWORD',
                'TENANT_ADMIN_ROLE_GRANT', 'TENANT_ADMIN_ROLE_REVOKE', 'USER_CREATED',
                'USER_DELETED', 'PASSWORD_RESET'
            ]),
            
            'security_events': ComplianceService.count_action(logs, [
                'ENCRYPTION_KEY_GENERATE', 'ENCRYPTION_KEY_ROTATE', 'SECRET_MODIFY',
                'SECURITY_CONFIG_CHANGE', 'SYSTEM_ADMIN_ACCESS_DENIED', 'ACCESS_DENIED',
                'SECURITY_VIOLATION'
            ]),
            
            'tenant_management': ComplianceService.count_action(logs, [
                'TENANT_CREATE', 'TENANT_DELETE', 'TENANT_ACTIVATE', 
                'TENANT_DEACTIVATE', 'TENANT_SUSPEND'
            ]),
            
            'config_changes': ComplianceService.count_action(logs, [
                'TENANT_CONFIG_CHANGE', 'SYSTEM_CONFIG_CHANGE', 'TENANT_SCHEMA_MODIFY',
                'SECURITY_BASELINE_UPDATE'
            ]),
            
            'database_operations': ComplianceService.count_action(logs, [
                'MASTER_DB_QUERY', 'MASTER_DB_SCHEMA_CHANGE', 'MIGRATION_RUN'
            ]),
            
            'system_operations': ComplianceService.count_action(logs, [
                'SYSTEM_BACKUP', 'SYSTEM_RESTORE', 'SYSTEM_MAINTENANCE'
            ]),
            
            'compliance_dashboard_access': ComplianceService.count_action(logs, [
                'COMPLIANCE_DASHBOARD_ACCESS'
            ]),
            'audit_log_access': ComplianceService.count_action(logs, [
                'AUDIT_LOG_ACCESS', 'SYSTEM_AUDIT_ACCESS'
            ]),
            'data_exports': ComplianceService.count_action(logs, [
                'COMPLIANCE_DATA_EXPORTED', 'DATA_EXPORT'
            ]),
            
            'retention_cleanups': ComplianceService.count_action(logs, [
                'RETENTION_CLEANUP', 'BIN_CLEANUP'
            ]),
        }
    
        unique_tenants = set()
        unique_users = set()
        
        for log in logs:
            if log['tenant_id'] and log['tenant_id'] not in ['SYSTEM', 'UNKNOWN']:
                unique_tenants.add(log['tenant_id'])
            if log['actor_email'] and log['actor_email'] != 'System':
                unique_users.add(log['actor_email'])
        
        summary.update({
            'unique_tenants': len(unique_tenants),
            'unique_users': len(unique_users),
            'success_rate': ComplianceService.calculate_success_rate(logs),
            'high_risk_events': ComplianceService.count_high_risk_events(logs)
        })
        
        return summary
    
    @staticmethod
    def count_action(logs, actions, success=None):
        if isinstance(actions, str):
            actions = [actions]
        count = 0
        for log in logs:
            if log['action'] in actions:
                if success is None:
                    count += 1
                elif success and log['result'] == 'SUCCESS':
                    count += 1
                elif not success and log['result'] == 'FAILURE':
                    count += 1
        return count

    @staticmethod
    def count_admin_actions(logs):
        admin_actions = ["TENANT_CREATE", "TENANT_DELETE", "TENANT_ADMIN_CREATE", "TENANT_ADMIN_DELETE", "SYSTEM_CONFIG_CHANGE", "TENANT_CONFIG_CHANGE"]
        return ComplianceService.count_action(logs, admin_actions)
    
    @staticmethod
    def count_security_events(logs):
        security_actions = ['SYSTEM_ADMIN_ACCESS_DENIED', 'ENCRYPTION_KEY_ROTATE','SECURITY_CONFIG_CHANGE', 'TENANT_DLP_SCAN']
        return ComplianceService.count_action(logs, security_actions)
    
    @staticmethod
    def count_high_risk_events(logs):
        count = 0
        for log in logs:
            if (log['severity'] in ['HIGH', 'CRITICAL'] or log['result'] == 'FAILURE' or 'DELETE' in log['action'] or 'ACCESS_DENIED' in log['action']):
                count += 1
        return count

    @staticmethod
    def calculate_success_rate(logs):
        if not logs:
            return 100.0
        successful = len([log for log in logs if log['result'] == 'SUCCESS'])
        return round((successful / len(logs)) * 100, 2)
    
    @staticmethod
    def determine_severity(action_type, success):
        if not success:
            return 'HIGH'
        high_severity_actions = [
            'TENANT_DELETE', 'TENANT_ADMIN_DELETE', 'ENCRYPTION_KEY_ROTATE',
            'SYSTEM_CONFIG_CHANGE', 'MASTER_DB_SCHEMA_CHANGE'
        ]
        if action_type in high_severity_actions:
            return 'HIGH'
        elif 'DELETE' in action_type or 'REMOVE' in action_type:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def mask_email_for_display(email):
        if not email or '@' not in email:
            return email
        
        local, domain = email.split('@')
        if len(local) > 2:
            masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
        else:
            masked_local = '*' * len(local)
        
        domain_parts = domain.split('.')
        masked_domain = domain_parts[0][0] + '*' * (len(domain_parts[0]) - 1)
        if len(domain_parts) > 1:
            masked_domain += '.' + '.'.join(domain_parts[1:])
        
        return f"{masked_local}@{masked_domain}"
    
    @staticmethod
    def mask_ip_address(ip):
        if not ip:
            return ip
        import re
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip)):
            parts = str(ip).split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.***.***.***"
        if len(str(ip)) > 6:
            return str(ip)[:4] + '*' * (len(str(ip)) - 4)
        
        return ip

    @staticmethod
    def mask_resource_id(resource_id):
        """Mask resource ID for display purposes"""
        if not resource_id:
            return resource_id
        
        resource_str = str(resource_id)
        if len(resource_str) <= 4:
            return '*' * len(resource_str)
        elif len(resource_str) <= 8:
            return resource_str[:2] + '*' * (len(resource_str) - 4) + resource_str[-2:]
        else:
            return resource_str[:4] + '*' * (len(resource_str) - 8) + resource_str[-4:]
        
    @staticmethod
    def exportComplianceCSV(logs, summary):
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['COMPLIANCE REPORT SUMMARY'])
        writer.writerow(['Generated On', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        writer.writerow(['Metric', 'Count'])
        for key, value in summary.items():
            writer.writerow([key.replace('_', ' ').title(), value])
        writer.writerow([])
        writer.writerow(['DETAILED AUDIT LOGS'])
        writer.writerow([
            'Timestamp', 'Tenant ID', 'Actor', 'Role', 'Action', 
            'Resource Type', 'Resource ID', 'Result', 'Severity', 'Details', 'IP Address'
        ])
        for log in logs:
            writer.writerow([
                log['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if log['timestamp'] else '',
                log['tenant_id'] or '',
                log['actor_email'] or '',
                log['actor_role'] or '',
                log['action'] or '',
                log['resource_type'] or '',
                log['resource_id'] or '',
                log['result'] or '',
                log['severity'] or '',
                log['details'] or '',
                log['ip_address'] or ''
            ])
        output.seek(0)
        return output.getvalue()
    
    @staticmethod
    def exportComplianceJSON(logs, summary):
        report_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'compliance_audit',
                'total_records': len(logs)
            },
            'summary': summary,
            'audit_logs': []
        }
        for log in logs:
            log_entry = dict(log)
            if log_entry['timestamp']:
                log_entry['timestamp'] = log_entry['timestamp'].isoformat()
            report_data['audit_logs'].append(log_entry)
        
        return json.dumps(report_data, indent=2, default=str)
    
    @staticmethod
    def exportCompliancePDF(logs, summary, start_date, end_date, tenant_name, generated_by):
        import tempfile
        import os
        from datetime import datetime
        try:
            temp_dir = tempfile.gettempdir()
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"compliance_report_{timestamp}.pdf"
            pdf_path = os.path.join(temp_dir, filename)
            masked_generated_by = ComplianceService.mask_email_for_display(generated_by)
            doc = SimpleDocTemplate(pdf_path, pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.HexColor('#1e3a8a')
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.HexColor('#1e40af')
            )
            normal_style = ParagraphStyle(
                'CustomNormal',
                parent=styles['Normal'],
                fontSize=10,
                spaceAfter=6
            )
            story.append(Paragraph("COMPLIANCE AUDIT REPORT", title_style))
            story.append(Spacer(1, 20))
            report_info_data = [
                ['Report Type:', 'Compliance Audit Export'],
                ['Scope:', tenant_name],
                ['Report Period:', f"{start_date.strftime('%d %b %Y')} – {end_date.strftime('%d %b %Y')}"],
                ['Generated On:', datetime.now().strftime('%d %b %Y at %H:%M')],
                ['Generated By:', masked_generated_by],  # Masked email
                ['Total Records:', str(len(logs))]
            ]
            report_info_table = Table(report_info_data, colWidths=[2*inch, 4*inch])
            report_info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e5e7eb')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d1d5db')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(report_info_table)
            story.append(Spacer(1, 30))
            story.append(Paragraph("Executive Summary", heading_style))
            summary_data = [
                ['Metric', 'Count', 'Details'],
                ['Total Events', str(summary.get('total_events', 0)), 'All logged activities'],
                ['Successful Logins', str(summary.get('successful_logins', 0)), 'User authentication success'],
                ['Failed Login Attempts', str(summary.get('failed_logins', 0)), 'Security concern if high'],
                ['File Operations', str(summary.get('file_uploads', 0) + summary.get('file_deletions', 0)), 'Upload + deletion activities'],
                ['Admin Actions', str(summary.get('admin_actions', 0)), 'Administrative operations'],
                ['Security Events', str(summary.get('security_events', 0)), 'Security-related activities'],
                ['High Risk Events', str(summary.get('high_risk_events', 0)), 'Events requiring attention'],
                ['Success Rate', f"{summary.get('success_rate', 0):.1f}%", 'Overall operation success'],
                ['Unique Users', str(summary.get('unique_users', 0)), 'Active user accounts']
            ]
            summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d1d5db')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')])
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 30))
            if logs:
                story.append(Paragraph("Detailed Audit Logs", heading_style))
                log_headers = ['Timestamp', 'Actor', 'Action', 'Resource', 'Result', 'Severity']
                log_data = [log_headers]
                
                for log in logs:
                    masked_log_data = [
                        log['timestamp'].strftime('%Y-%m-%d %H:%M') if log.get('timestamp') else '',
                        ComplianceService.mask_email_for_display(log.get('actor_email', '')),
                        log.get('action', ''),
                        log.get('resource_type', '')[:20] + '...' if len(str(log.get('resource_type', ''))) > 20 else log.get('resource_type', ''),
                        log.get('result', ''),
                        log.get('severity', '')
                    ]
                    log_data.append(masked_log_data)
                logs_table = Table(log_data, colWidths=[1.2*inch, 1.8*inch, 1.2*inch, 1.2*inch, 0.8*inch, 0.8*inch])
                logs_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, 0), 8),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
                    ('WORDWRAP', (0, 0), (-1, -1), True)
                ]))
                
                story.append(logs_table)
            else:
                story.append(Paragraph("No audit logs found for the specified period.", normal_style))
            story.append(Spacer(1, 30))
            privacy_notice = Paragraph(
                "<b>Privacy Notice:</b> Sensitive information in this report has been masked for privacy and security purposes. "
                "Email addresses, IP addresses, and other personally identifiable information are partially obscured.",
                ParagraphStyle('PrivacyNotice', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#6b7280'))
            )
            story.append(privacy_notice)
            doc.build(story)
            
            print(f"PDF generated successfully: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            print(f"Error generating PDF: {e}")
            import traceback
            traceback.print_exc()
            return None
import os
import json
from datetime import datetime, timedelta
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from database import MasterSessionLocal
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import pandas as pd

class ComplianceService:
    COMPLIANCE_FRAMEWORKS = {
        'GDPR': {
            'name': 'General Data Protection Regulation',
            'required_metrics': ['data_subject_requests', 'data_breaches', 'consent_records', 'data_retention'],
            'report_frequency': 'quarterly'
        },
        'HIPAA': {
            'name': 'Health Insurance Portability and Accountability Act',
            'required_metrics': ['phi_access_logs', 'security_incidents', 'risk_assessments'],
            'report_frequency': 'annual'
        },
        'SOX': {
            'name': 'Sarbanes-Oxley Act',
            'required_metrics': ['financial_data_access', 'change_controls', 'audit_trails'],
            'report_frequency': 'quarterly'
        },
        'PCI_DSS': {
            'name': 'Payment Card Industry Data Security Standard',
            'required_metrics': ['cardholder_data_access', 'vulnerability_scans', 'security_tests'],
            'report_frequency': 'quarterly'
        }
    }

    @staticmethod
    def generateComplianceReport(tenantID, framework, startDate, endDate, generatedBy):
        try:
            reportData = ComplianceService.collectComplianceData(tenantID, framework, startDate, endDate)
            reportID = ComplianceService.createReportRecord(tenantID, framework, startDate, endDate, generatedBy)
            pdfPath = ComplianceService.createPDFReport(reportID, tenantID, framework, reportData, startDate, endDate)
            ComplianceService.updateReportFilePath(reportID, pdfPath)
            return {'status': True, 'report_id': reportID, 'pdf_path': pdfPath, 'data': reportData}
        except Exception as e:
            return {'status': False, 'error': str(e)}
        
    @staticmethod
    def collectComplianceData(tenantID, framework, startDate, endDate):
        data={}
        with MasterSessionLocal() as session:
            session.execute(text(f"SET search_path TO tenant_{tenantID}, public"))
            if framework == 'GDPR':
                data = ComplianceService.collectGDPRData(session, startDate, endDate)
            elif framework == 'HIPAA':
                data = ComplianceService.collectHIPAAData(session, startDate, endDate)
            elif framework == 'SOX':
                data = ComplianceService.collectSOXData(session, startDate, endDate)
            elif framework == 'PCI_DSS':
                data = ComplianceService.collectPCIDSSData(session, startDate, endDate)
        return data
    
    @staticmethod
    def collectGDPRData(session, startDate, endDate):
        data = {}
        dsarQuery = text("""
            SELECT COUNT(*) AS count, status
            FROM data_subject_requests
            WHERE created_at BETWEEN :start_date AND :end_date
            GROUP BY status
        """)
        dsarResults = session.execute(dsarQuery, {'start_date': startDate, 'end_date': endDate}).fetchall()
        data['data_subject_requests'] = {row['status']: row['count'] for row in dsarResults}
        breachQuery = text("""
            SELECT COUNT(*) AS count, severity
            FROM security_incidents
            WHERE incident_type = 'DATA_BREACH' AND reported_at BETWEEN :start_date AND :end_date
            GROUP BY severity
        """)
        breachResults = session.execute(breachQuery, {'start_date': startDate, 'end_date': endDate}).fetchall()
        data['data_breaches'] = {row['severity']: row['count'] for row in breachResults}
        accessQuery = text("""
            SELECT COUNT(*) AS total_accesses,
            COUNT(DISTINCT user_id) AS unique_users,
            COUNT(DISTINCT file_id) AS files_accessed
            FROM audit_logs
            WHERE action_type = 'FILE_ACCESS' AND created_at BETWEEN :start_date AND :end_date
        """)
        accessResults = session.execute(accessQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['file_access_summary'] = {
            'total_accesses': accessResults.total_accesses or 0,
            'unique_users': accessResults.unique_users or 0,
            'files_accessed': accessResults.files_accessed or 0
        }
        return data
    
    @staticmethod
    def collectHIPAAData(session, startDate, endDate):
        data = {}
        phiAccessQuery = text("""
            SELECT COUNT(*) AS authorized_access,
                COUNT(CASE WHEN status = 'FAILED' THEN 1 END) AS unauthorized_attempts
            FROM audit_logs 
            WHERE action_type IN ('PHI_ACCESS', 'MEDICAL_RECORD_ACCESS')
            AND created_at BETWEEN :start_date AND :end_date
        """)
        phiResults = session.execute(phiAccessQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['phi_access_logs'] = {
            'authorized': phiResults.authorized_access or 0,
            'unauthorized_attempts': phiResults.unauthorized_attempts or 0
        }
        securityIncidentsQuery = text("""
            SELECT COUNT(*) AS count, status, severity
            FROM security_incidents 
            WHERE incident_type IN ('PHI_BREACH', 'UNAUTHORIZED_ACCESS', 'SYSTEM_COMPROMISE')
            AND occurred_at BETWEEN :start_date AND :end_date
            GROUP BY status, severity
        """)
        securityResults = session.execute(securityIncidentsQuery, {'start_date': startDate, 'end_date': endDate}).fetchall()
        data['security_incidents'] = {
            'total': len(securityResults),
            'by_status': {},
            'by_severity': {}
        }
        for row in securityResults:
            data['security_incidents']['by_status'][row.status] = data['security_incidents']['by_status'].get(row.status, 0) + row.count
            data['security_incidents']['by_severity'][row.severity] = data['security_incidents']['by_severity'].get(row.severity, 0) + row.count
        riskAssessmentsQuery = text("""
            SELECT COUNT(*) AS total,
                COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) AS completed,
                COUNT(CASE WHEN status = 'PENDING' THEN 1 END) AS pending
            FROM risk_assessments 
            WHERE assessment_type = 'HIPAA_COMPLIANCE'
            AND created_at BETWEEN :start_date AND :end_date
        """)
        riskResults = session.execute(riskAssessmentsQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['risk_assessments'] = {
            'total': riskResults.total or 0,
            'completed': riskResults.completed or 0,
            'pending': riskResults.pending or 0
        }
        baaQuery = text("""
            SELECT COUNT(*) AS total_agreements,
                COUNT(CASE WHEN status = 'ACTIVE' THEN 1 END) AS active,
                COUNT(CASE WHEN expiry_date < CURRENT_DATE THEN 1 END) AS expired
            FROM business_associate_agreements
        """)
        baaResults = session.execute(baaQuery).fetchone()
        data['business_associate_agreements'] = {
            'total': baaResults.total_agreements or 0,
            'active': baaResults.active or 0,
            'expired': baaResults.expired or 0
        }
        return data
    @staticmethod
    def collectSOXData(session, startDate, endDate):
        data = {}
        financialAccessQuery = text("""
            SELECT COUNT(*) AS total_access,
                COUNT(DISTINCT user_id) AS unique_users,
                COUNT(CASE WHEN user_role = 'ADMIN' THEN 1 END) AS admin_access
            FROM audit_logs 
            WHERE action_type IN ('FINANCIAL_DATA_ACCESS', 'REPORT_GENERATION', 'FINANCIAL_RECORD_VIEW')
            AND created_at BETWEEN :start_date AND :end_date
        """)
        financialResults = session.execute(financialAccessQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['financial_data_access'] = {
            'total_access': financialResults.total_access or 0,
            'unique_users': financialResults.unique_users or 0,
            'admin_access': financialResults.admin_access or 0
        }
        changeControlQuery = text("""
            SELECT COUNT(*) AS total_changes,
                COUNT(CASE WHEN approval_status = 'APPROVED' THEN 1 END) AS approved_changes,
                COUNT(CASE WHEN change_type = 'EMERGENCY' THEN 1 END) AS emergency_changes,
                COUNT(CASE WHEN approval_status = 'PENDING' THEN 1 END) AS pending_approval
            FROM change_requests 
            WHERE requested_at BETWEEN :start_date AND :end_date
        """)
        changeResults = session.execute(changeControlQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['change_controls'] = {
            'total_changes': changeResults.total_changes or 0,
            'approved_changes': changeResults.approved_changes or 0,
            'emergency_changes': changeResults.emergency_changes or 0,
            'pending_approval': changeResults.pending_approval or 0
        }
        auditTrailQuery = text("""
            SELECT COUNT(*) AS total_events,
                COUNT(CASE WHEN event_type = 'LOGIN' THEN 1 END) AS login_events,
                COUNT(CASE WHEN event_type = 'DATA_MODIFICATION' THEN 1 END) AS data_changes,
                COUNT(CASE WHEN integrity_check = 'FAILED' THEN 1 END) AS integrity_failures
            FROM audit_logs 
            WHERE created_at BETWEEN :start_date AND :end_date
        """)
        auditResults = session.execute(auditTrailQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['audit_trails'] = {
            'total_events': auditResults.total_events or 0,
            'login_events': auditResults.login_events or 0,
            'data_changes': auditResults.data_changes or 0,
            'integrity_failures': auditResults.integrity_failures or 0,
            'trail_complete': (auditResults.integrity_failures or 0) == 0
        }
        controlsQuery = text("""
            SELECT COUNT(*) AS total_tests,
                COUNT(CASE WHEN test_result = 'PASSED' THEN 1 END) AS passed_tests,
                COUNT(CASE WHEN test_result = 'FAILED' THEN 1 END) AS failed_tests
            FROM internal_control_tests 
            WHERE test_date BETWEEN :start_date AND :end_date
        """)
        controlsResults = session.execute(controlsQuery, {'start_date': startDate, 'end_date': endDate}).fetchone()
        data['internal_controls'] = {
            'total_tests': controlsResults.total_tests or 0,
            'passed_tests': controlsResults.passed_tests or 0,
            'failed_tests': controlsResults.failed_tests or 0
        }
        return data
    
    @staticmethod
    def collectPCIDSSData(session, startDate, endDate):
        data = {}
        cardholderAccessQuery = text("""
            SELECT COUNT(*) AS total_access,
                COUNT(CASE WHEN access_encrypted = true THEN 1 END) AS encrypted_access,
                COUNT(CASE WHEN status = 'FAILED' THEN 1 END) AS failed_attempts,
                COUNT(DISTINCT user_id) AS unique_users
            FROM audit_logs 
            WHERE action_type IN ('CARDHOLDER_DATA_ACCESS', 'PAYMENT_PROCESSING', 'CARD_DATA_VIEW')
            AND created_at BETWEEN :start_date AND :end_date
        """)
        cardholderResults = session.execute(cardholderAccessQuery, {
            'start_date': startDate, 'end_date': endDate
        }).fetchone()
        data['cardholder_data_access'] = {
            'total_access': cardholderResults.total_access or 0,
            'encrypted_access': cardholderResults.encrypted_access or 0,
            'failed_attempts': cardholderResults.failed_attempts or 0,
            'unique_users': cardholderResults.unique_users or 0
        }
        vulnScanQuery = text("""
            SELECT COUNT(*) AS total_scans,
                COUNT(CASE WHEN scan_status = 'PASSED' THEN 1 END) AS passed_scans,
                COUNT(CASE WHEN scan_status = 'FAILED' THEN 1 END) AS failed_scans,
                AVG(vulnerabilities_found) AS avg_vulnerabilities
            FROM vulnerability_scans 
            WHERE scan_date BETWEEN :start_date AND :end_date
        """)
        vulnResults = session.execute(vulnScanQuery, {
            'start_date': startDate, 'end_date': endDate
        }).fetchone()
        data['vulnerability_scans'] = {
            'total_scans': vulnResults.total_scans or 0,
            'passed_scans': vulnResults.passed_scans or 0,
            'failed_scans': vulnResults.failed_scans or 0,
            'avg_vulnerabilities': float(vulnResults.avg_vulnerabilities or 0)
        }
        securityTestQuery = text("""
            SELECT COUNT(*) AS total_tests,
                COUNT(CASE WHEN test_type = 'PENETRATION_TEST' THEN 1 END) AS penetration_tests,
                COUNT(CASE WHEN test_type = 'SECURITY_SCAN' THEN 1 END) AS security_scans,
                SUM(issues_found) AS total_issues_found
            FROM security_tests 
            WHERE test_date BETWEEN :start_date AND :end_date
        """)
        securityResults = session.execute(securityTestQuery, {
            'start_date': startDate, 'end_date': endDate
        }).fetchone()
        data['security_tests'] = {
            'total_tests': securityResults.total_tests or 0,
            'penetration_tests': securityResults.penetration_tests or 0,
            'security_scans': securityResults.security_scans or 0,
            'total_issues_found': securityResults.total_issues_found or 0
        }
        networkSegQuery = text("""
            SELECT COUNT(*) AS total_segments,
                COUNT(CASE WHEN segment_isolated = true THEN 1 END) AS isolated_segments,
                COUNT(CASE WHEN firewall_configured = true THEN 1 END) AS firewall_protected
            FROM network_segments
            WHERE segment_type = 'CARDHOLDER_DATA_ENVIRONMENT'
        """)
        networkResults = session.execute(networkSegQuery).fetchone()
        data['network_segmentation'] = {
            'total_segments': networkResults.total_segments or 0,
            'isolated_segments': networkResults.isolated_segments or 0,
            'firewall_protected': networkResults.firewall_protected or 0
        }
        encryptionQuery = text("""
            SELECT COUNT(*) AS total_data_stores,
                COUNT(CASE WHEN encryption_status = 'ENCRYPTED' THEN 1 END) AS encrypted_stores,
                COUNT(CASE WHEN encryption_algorithm IN ('AES-256', 'RSA-2048') THEN 1 END) AS strong_encryption
            FROM data_stores
            WHERE data_type = 'CARDHOLDER_DATA'
        """)
        encryptionResults = session.execute(encryptionQuery).fetchone()
        data['encryption_status'] = {
            'total_data_stores': encryptionResults.total_data_stores or 0,
            'encrypted_stores': encryptionResults.encrypted_stores or 0,
            'strong_encryption': encryptionResults.strong_encryption or 0
        }
        return data
    
    @staticmethod
    def createReportRecord(tenantID, framework, startDate, endDate, generatedBy):
        with MasterSessionLocal() as session:
            insertQuery = text("""
                INSERT INTO compliance_reports 
                (tenant_id, report_type, report_period_start, report_period_end, generated_by, status)
                VALUES (:tenant_id, :framework, :start_date, :end_date, :generated_by, 'GENERATING')
                RETURNING id
            """)
            result = session.execute(insertQuery, {
                'tenant_id': tenantID,
                'framework': framework,
                'start_date': startDate,
                'end_date': endDate,
                'generated_by': generatedBy
            })
            reportID = result.fetchone()[0]
            session.commit()
            return reportID
    
    @staticmethod
    def createPDFReport(reportID, tenantID, framework, reportData, startDate, endDate):
        os.makedirs('compliance_reports', exist_ok=True)
        filename = f"compliance_reports/report_{reportID}"
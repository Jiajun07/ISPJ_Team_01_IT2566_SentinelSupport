from flask import Blueprint, session, abort, Response, request, redirect, url_for, send_file
from datetime import datetime, timedelta
from ComplianceService.services.complianceservice import ComplianceService
from AuditService.LogService import SysLogService
import os
import tempfile

export_bp = Blueprint('export', __name__)

@export_bp.route("/export/compliance/csv")
def export_compliance_csv():
    if 'tenant_id' not in session:
        return redirect(url_for('home'))
    user_role = session.get('user_type')
    tenant_id = session.get('tenant_id')
    if user_role not in ["super_admin", "tenant_admin"]:
        abort(403)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    try:
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        else:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
    except ValueError:
        abort(400)
    if user_role == "super_admin":
        logs, summary = ComplianceService.generateComplianceData(
            startDate=start_date, 
            endDate=end_date
        )
        filename = f"platform_compliance_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    else: 
        logs, summary = ComplianceService.generateComplianceData(
            tenantID=tenant_id,
            startDate=start_date,
            endDate=end_date
        )
        filename = f"tenant_{tenant_id}_compliance_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    csv_data = ComplianceService.exportComplianceCSV(logs, summary)
    
    SysLogService.logTheEvent(
        action_type='COMPLIANCE_DATA_EXPORTED',
        description=f"Compliance data exported as CSV by {session.get('email')} - {len(logs)} records",
        category='COMPLIANCE',
        target_resource='EXPORT',
        additional_data={
            'export_format': 'CSV',
            'record_count': len(logs),
            'date_range': f"{start_date.date()} to {end_date.date()}",
            'filename': filename
        },
        tenant_id=tenant_id
    )
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@export_bp.route("/export/compliance/json")
def export_compliance_json():
    if 'tenant_id' not in session:
        return redirect(url_for('home'))
    user_role = session.get('user_type')
    tenant_id = session.get('tenant_id')
    if user_role not in ["super_admin", "tenant_admin"]:
        abort(403)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    try:
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        else:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
    except ValueError:
        abort(400)
    if user_role == "super_admin":
        logs, summary = ComplianceService.generateComplianceData(
            startDate=start_date, 
            endDate=end_date
        )
        filename = f"platform_compliance_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    else: 
        logs, summary = ComplianceService.generateComplianceData(
            tenantID=tenant_id,
            startDate=start_date,
            endDate=end_date
        )
        filename = f"tenant_{tenant_id}_compliance_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    json_data = ComplianceService.exportComplianceJSON(logs, summary)
    
    SysLogService.logTheEvent(
        action_type='COMPLIANCE_DATA_EXPORTED',
        description=f"Compliance data exported as JSON by {session.get('email')} - {len(logs)} records",
        category='COMPLIANCE',
        target_resource='EXPORT',
        additional_data={
            'export_format': 'JSON',
            'record_count': len(logs),
            'date_range': f"{start_date.date()} to {end_date.date()}",
            'filename': filename
        },
        tenant_id=tenant_id
    )
    
    return Response(
        json_data,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@export_bp.route("/export/compliance/pdf")
def export_compliance_pdf():
    if 'tenant_id' not in session:
        return redirect(url_for('home'))
    user_role = session.get('user_type')
    tenant_id = session.get('tenant_id')
    if user_role not in ["super_admin", "tenant_admin"]:
        abort(403)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        else:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
    except ValueError:
        abort(400)
    if user_role == "super_admin":
        logs, summary = ComplianceService.generateComplianceData(
            startDate=start_date, 
            endDate=end_date
        )
        tenant_name = "All Tenants (Platform-wide)"
        filename = f"platform_compliance_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    else:
        logs, summary = ComplianceService.generateComplianceData(
            tenantID=tenant_id,
            startDate=start_date,
            endDate=end_date
        )
        tenant_name = f"Tenant {tenant_id}"
        filename = f"tenant_{tenant_id}_compliance_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = ComplianceService.exportCompliancePDF(
        logs, summary, start_date, end_date, 
        tenant_name, session.get('email', 'System')
    )
    
    SysLogService.logTheEvent(
        action_type='COMPLIANCE_DATA_EXPORTED',
        description=f"Compliance data exported as PDF by {session.get('email')} - {len(logs)} records",
        category='COMPLIANCE',
        target_resource='EXPORT',
        additional_data={
            'export_format': 'PDF',
            'record_count': len(logs),
            'date_range': f"{start_date.date()} to {end_date.date()}",
            'filename': filename
        },
        tenant_id=tenant_id
    )
    
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )
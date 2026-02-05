from flask import Blueprint, render_template, request, session, abort, flash, redirect, url_for
from datetime import datetime, timedelta
from ComplianceService.services.complianceservice import ComplianceService
from AuditService.LogService import SysLogService

compliance_bp = Blueprint('compliance', __name__)

@compliance_bp.route('/compliance-dashboard')
def compliance_dashboard():
    user_role = session.get('user_type')
    if user_role not in ['superadmin', 'tenant_admin']:
        return redirect(url_for('login'))
    if user_role == 'tenant_admin' and 'tenant_id' not in session:
        return redirect(url_for('login'))
    user_role = session.get('user_type')
    tenant_id = session.get('tenant_id')
    if user_role == "superadmin":
        logs, summary = ComplianceService.generateComplianceData()
        scope = "Platform-wide"
    elif user_role == "tenant_admin":
        logs, summary = ComplianceService.generateComplianceData(tenantID=tenant_id)
        scope = f"Tenant {tenant_id}"
    else:
        abort(403)
    SysLogService.logTheEvent(
        action_type='COMPLIANCE_DASHBOARD_ACCESS',
        description=f"Compliance dashboard accessed by {session.get('email')}",
        category='COMPLIANCE',
        target_resource='DASHBOARD',
        tenant_id=tenant_id
    )
    return render_template('compliance/dashboard.html', 
                         logs=logs[:50],
                         summary=summary,
                         scope=scope,
                         user_role=user_role)

@compliance_bp.route('/compliance-report')
def compliance_report():
    user_role = session.get('user_type')
    if user_role not in ['superadmin', 'tenant_admin']:
        return redirect(url_for('login'))
    if user_role == 'tenant_admin' and 'tenant_id' not in session:
        return redirect(url_for('login'))
    user_role = session.get('user_type')
    tenant_id = session.get('tenant_id')
    if user_role not in ["superadmin", "tenant_admin"]:
        abort(403)
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    try:
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        else:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=30)
    except ValueError:
        flash('Invalid date format', 'error')
        return redirect(url_for('compliance.compliance_dashboard'))
    if user_role == "superadmin":
        logs, summary = ComplianceService.generateComplianceData(
            startDate=start_date, 
            endDate=end_date
        )
        scope = "All Tenants"
    else:
        logs, summary = ComplianceService.generateComplianceData(
            tenantID=tenant_id,
            startDate=start_date,
            endDate=end_date
        )
        scope = f"Tenant {tenant_id}"
    SysLogService.logTheEvent(
        action_type='COMPLIANCE_REPORT_GENERATED',
        description=f"Compliance report generated for {scope} ({start_date_str} to {end_date_str})",
        category='COMPLIANCE',
        target_resource='REPORT',
        additional_data={
            'date_range': f"{start_date_str} to {end_date_str}",
            'scope': scope,
            'total_events': len(logs)
        },
        tenant_id=tenant_id
    )
    return render_template('compliance/report.html',
                         logs=logs,
                         summary=summary,
                         scope=scope,
                         start_date=start_date_str,
                         end_date=end_date_str,
                         user_role=user_role)


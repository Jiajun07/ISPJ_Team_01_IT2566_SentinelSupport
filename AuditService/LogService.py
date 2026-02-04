import json
import logging
from sqlalchemy.exc import SQLAlchemyError
from database import MasterSessionLocal, db
from models import SystemAuditLog
from datetime import datetime
from flask import request, session, g

logger = logging.getLogger(__name__)

class SysLogService:
    ACTION_TYPES = {
        'TENANT_CREATE': 'TENANT_CREATE',
        'TENANT_DELETE': 'TENANT_DELETE',
        'TENANT_ACTIVATE': 'TENANT_ACTIVATE',
        'TENANT_DEACTIVATE': 'TENANT_DEACTIVATE',
        'TENANT_SUSPEND': 'TENANT_SUSPEND',
        
        'TENANT_ACCESS': 'TENANT_ACCESS',
        'TENANT_CONTEXT_SWITCH': 'TENANT_CONTEXT_SWITCH',
        'TENANT_DATABASE_ACCESS': 'TENANT_DATABASE_ACCESS',
        'CROSS_TENANT_QUERY': 'CROSS_TENANT_QUERY',
        
        'TENANT_QUOTA_MODIFY': 'TENANT_QUOTA_MODIFY',
        'TENANT_CONFIG_CHANGE': 'TENANT_CONFIG_CHANGE',
        'TENANT_SCHEMA_MODIFY': 'TENANT_SCHEMA_MODIFY',
        
        'TENANT_ADMIN_CREATE': 'TENANT_ADMIN_CREATE',
        'TENANT_ADMIN_DELETE': 'TENANT_ADMIN_DELETE',
        'TENANT_ADMIN_RESET_PASSWORD': 'TENANT_ADMIN_RESET_PASSWORD',
        'TENANT_ADMIN_ROLE_GRANT': 'TENANT_ADMIN_ROLE_GRANT',
        'TENANT_ADMIN_ROLE_REVOKE': 'TENANT_ADMIN_ROLE_REVOKE',
        
        'ENCRYPTION_KEY_GENERATE': 'ENCRYPTION_KEY_GENERATE',
        'ENCRYPTION_KEY_ROTATE': 'ENCRYPTION_KEY_ROTATE',
        'SECRET_MODIFY': 'SECRET_MODIFY',
        'SECURITY_CONFIG_CHANGE': 'SECURITY_CONFIG_CHANGE',
        
        'SYSTEM_BACKUP': 'SYSTEM_BACKUP',
        'SYSTEM_RESTORE': 'SYSTEM_RESTORE',
        'SYSTEM_MAINTENANCE': 'SYSTEM_MAINTENANCE',
        'SYSTEM_CONFIG_CHANGE': 'SYSTEM_CONFIG_CHANGE',
        
        'MASTER_DB_QUERY': 'MASTER_DB_QUERY',
        'MASTER_DB_SCHEMA_CHANGE': 'MASTER_DB_SCHEMA_CHANGE',
        'MIGRATION_RUN': 'MIGRATION_RUN',
        
        'SYSTEM_ADMIN_LOGIN': 'SYSTEM_ADMIN_LOGIN',
        'SYSTEM_ADMIN_LOGOUT': 'SYSTEM_ADMIN_LOGOUT',
        'SYSTEM_ADMIN_ACCESS_DENIED': 'SYSTEM_ADMIN_ACCESS_DENIED',

        'TENANT_USER_LOGIN': 'TENANT_USER_LOGIN',
        'TENANT_USER_LOGOUT': 'TENANT_USER_LOGOUT',
        'TENANT_FILE_UPLOAD': 'TENANT_FILE_UPLOAD',
        'TENANT_FILE_DELETE': 'TENANT_FILE_DELETE',
        'TENANT_FILE_SHARE': 'TENANT_FILE_SHARE',
        'TENANT_DLP_SCAN': 'TENANT_DLP_SCAN',
        'TENANT_POLICY_CHANGE': 'TENANT_POLICY_CHANGE'
    }
    
    CATEGORIES = {
        'TENANT_MANAGEMENT': 'TENANT_MANAGEMENT',
        'TENANT_ACCESS': 'TENANT_ACCESS',
        'ADMIN_MANAGEMENT': 'ADMIN_MANAGEMENT',
        'SECURITY': 'SECURITY',
        'SYSTEM': 'SYSTEM',
        'DATABASE': 'DATABASE',
        'FILE_MANAGEMENT': 'FILE_MANAGEMENT',
        'USER_ACTIVITY': 'USER_ACTIVITY'
    }
    
    RISK_LEVELS = {
        'HIGH': 'HIGH',
        'CRITICAL': 'CRITICAL'
    }
    
    @staticmethod
    def logTheEvent(action_type, description, **kwargs):
        try:
            client_ip = SysLogService.getClientIP()
            user_agent = request.headers.get('User-Agent', 'Unknown') if request else 'System'
            tenant_id = kwargs.get('tenant_id')
            if not tenant_id:
                if kwargs.get('is_system_admin', False) or action_type.startswith('SYSTEM_ADMIN'):
                    tenant_id = "SYSTEM"
                else:
                    tenant_id = session.get('tenant_id', 'UNKNOWN')
            audit_entry = SystemAuditLog(
                admin_id=kwargs.get('admin_id') or session.get('admin_id'),
                admin_email=kwargs.get('admin_email') or session.get('admin_email'),
                action_type=action_type,
                action_category=kwargs.get('category', SysLogService.determineCat(action_type)),
                action_description=description,
                target_tenant_id=tenant_id,
                target_resource=kwargs.get('target_resource'),
                resource_id=kwargs.get('resource_id'),
                ip_address=client_ip,
                user_agent=user_agent[:500] if user_agent else None,
                success=kwargs.get('success', True),
                before_state=json.dumps(kwargs.get('before_state')) if kwargs.get('before_state') else None,
                after_state=json.dumps(kwargs.get('after_state')) if kwargs.get('after_state') else None,
                additional_data=json.dumps(kwargs.get('additional_data')) if kwargs.get('additional_data') else None,
                created_at=datetime.utcnow()
            )
            with MasterSessionLocal() as db_session:
                db_session.add(audit_entry)
                db_session.commit()
                logger.info(f"System admin audit log created: {action_type} - {description}")   
        except Exception as e:
            logger.error(f"Failed to create system admin audit log: {str(e)}", exc_info=True)

    @staticmethod
    def logSystemAdminEvent(action_type, description, **kwargs):
        kwargs['is_system_admin'] = True
        SysLogService.logTheEvent(action_type, description, **kwargs)
    
    @staticmethod
    def logTenantEvent(tenant_id,action_type, description, **kwargs):
        kwargs['tenant_id'] = str(tenant_id)
        SysLogService.logTheEvent(action_type, description, **kwargs)
    
    @staticmethod
    def getSysLogs(limit=100, offset=0, filters=None):
        try:
            with MasterSessionLocal() as db_session:
                query = db_session.query(SystemAuditLog)
                if filters:
                    if filters.get('tenant_id'):
                        query = query.filter(SystemAuditLog.target_tenant_id == str(filters['tenant_id']))
                    if filters.get('action_type'):
                        query = query.filter(SystemAuditLog.action_type == filters['action_type'])
                    if filters.get('category'):
                        query = query.filter(SystemAuditLog.action_category == filters['category'])
                    if filters.get('target_tenant_id'):
                        query = query.filter(SystemAuditLog.target_tenant_id == filters['target_tenant_id'])
                    if filters.get('admin_email'):
                        query = query.filter(SystemAuditLog.admin_email.ilike(f"%{filters['admin_email']}%"))
                    if filters.get('start_date'):
                        query = query.filter(SystemAuditLog.created_at >= filters['start_date'])
                    if filters.get('end_date'):
                        query = query.filter(SystemAuditLog.created_at <= filters['end_date'])
                    if filters.get('success') is not None:
                        query = query.filter(SystemAuditLog.success == filters['success'])
                total_count = query.count()
                logs = query.order_by(SystemAuditLog.created_at.desc()).offset(offset).limit(limit).all()
                return {
                    'total_count': total_count,
                    'logs': [log.to_dict() for log in logs],
                    'has_more': (offset + limit) < total_count
                }
        except Exception as e:
            logger.error(f"Failed to retrieve system audit logs: {str(e)}")
            return {
                'total_count': 0,
                'logs': [],
                'has_more': False
            }
        
    @staticmethod
    def getSysStats(filters=None):
        try:
            with MasterSessionLocal() as db_session:
                query = db_session.query(SystemAuditLog)
                if filters:
                    if filters.get('tenant_id'):
                        query = query.filter(SystemAuditLog.target_tenant_id == str(filters['tenant_id']))
                    if filters.get('start_date'):
                        query = query.filter(SystemAuditLog.created_at >= filters['start_date'])
                    if filters.get('end_date'):
                        query = query.filter(SystemAuditLog.created_at <= filters['end_date'])
                total_events = query.count()
                failed_events = query.filter(SystemAuditLog.success == False).count()
                category_counts = {}
                for category in SysLogService.CATEGORIES.values():
                    count = query.filter(SystemAuditLog.action_category == category).count()
                    category_counts[category] = count
                tenant_activity = {}
                tenant_logs = query.filter(SystemAuditLog.target_tenant_id.isnot(None)).all()
                for log in tenant_logs:
                    tenant_id = log.target_tenant_id
                    if tenant_id not in tenant_activity:
                        tenant_activity[tenant_id] = 0
                    tenant_activity[tenant_id] += 1
                return {
                    'total_events': total_events,
                    'failed_events': failed_events,
                    'success_rate': round(((total_events - failed_events) / total_events * 100) if total_events > 0 else 0, 2),
                    'category_counts': category_counts,
                    'tenant_activity': tenant_activity
                }
        except Exception as e:
            logger.error(f"Failed to retrieve system audit statistics: {str(e)}")
            return {'total_events': 0, 'failed_events': 0, 'success_rate': 0, 'category_counts': {}, 'tenant_activity': {}}
        
    @staticmethod
    def getClientIP():
        if request:
            return request.environ.get('HTTP_X_REAL_IP', request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr))
        return 'SYSTEM'
    
    @staticmethod
    def determineCat(action_type):
        if action_type.startswith('TENANT_') and not action_type.startswith('TENANT_ADMIN'):
            return 'TENANT_MANAGEMENT'
        elif action_type.startswith('TENANT_ADMIN'):
            return 'ADMIN_MANAGEMENT'
        elif 'ACCESS' in action_type or 'CONTEXT' in action_type:
            return 'USER_ACTIVITY'
        elif action_type.startswith('TENANT_FILE'):
            return 'FILE_MANAGEMENT'
        elif 'ACCESS' in action_type or 'CONTEXT' in action_type:
            return 'TENANT_ACCESS'
        elif action_type.startswith('ENCRYPTION') or action_type.startswith('SECRET') or action_type.startswith('SECURITY'):
            return 'SECURITY'
        elif action_type.startswith('MASTER_DB') or action_type.startswith('MIGRATION') or 'QUERY' in action_type:
            return 'DATABASE'
        else:
            return 'SYSTEM'
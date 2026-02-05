from database import db
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class SystemAuditLog(db.Model):
    __tablename__ = 'system_audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.String(100), nullable=True)  
    admin_email = db.Column(db.String(255), nullable=True)  
    action_type = db.Column(db.String(50), nullable=False, index=True)
    action_category = db.Column(db.String(30), nullable=False, index=True)
    action_description = db.Column(db.Text, nullable=False)
    target_tenant_id = db.Column(db.String(50), nullable=True, index=True)  
    target_resource = db.Column(db.String(100), nullable=True)  
    resource_id = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, default=True)
    before_state = db.Column(db.Text, nullable=True)  
    after_state = db.Column(db.Text, nullable=True)   
    additional_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f'<SystemAuditLog {self.id}: {self.action_type} by {self.admin_email}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'admin_id': self.admin_id,
            'admin_email': self.admin_email,
            'action_type': self.action_type,
            'action_category': self.action_category,
            'action_description': self.action_description,
            'target_tenant_id': self.target_tenant_id,
            'target_resource': self.target_resource,
            'resource_id': self.resource_id,
            'ip_address': self.ip_address,
            'success': self.success,
            'before_state': self.before_state,
            'after_state': self.after_state,
            'additional_data': self.additional_data,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
class ComplianceReport(Base):
    __tablename__ = 'compliance_reports'
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(50), nullable=False, index=True)
    report_type = Column(String(50), nullable=False)
    report_period_start = Column(DateTime, nullable=False)
    report_period_end = Column(DateTime, nullable=False)
    status = Column(String(20), default='DRAFT')
    generated_by = Column(String(100), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)
    approved_by = Column(String(100))
    approved_at = Column(DateTime)
    file_path = Column(String(500))
    report_metadata = Column(JSON)

class ComplianceMetric(Base):
    __tablename__ = 'compliance_metrics'
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False)
    metric_type = Column(String(50), nullable=False)
    metric_value = Column(String(200), nullable=False)
    recorded_at = Column(DateTime, default=datetime.utcnow)
    compliance_framework = Column(String(50))
    description = Column(Text)

class ComplianceViolation(Base):
    __tablename__ = 'compliance_violations'
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False)
    violation_type = Column(String(100), nullable=False)
    severity = Column(String(20))
    detected_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)
    status = Column(String(20), default='OPEN')
    description = Column(Text)
    remediation_notes = Column(Text)
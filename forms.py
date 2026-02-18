from flask import Flask, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import (StringField, TextAreaField, SelectField, SubmitField, DateField, TimeField, PasswordField,
                     RadioField, FieldList, FormField, BooleanField, IntegerField)
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, Regexp, NumberRange
from flask_wtf.file import FileAllowed, FileField
from markupsafe import escape
from datetime import datetime, timedelta
import re



def password_complexity_check(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if len(password) > 64:
        raise ValidationError("Password must be less than 64 characters.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one digit.")
    if not re.search(r"[@$!%*?&]", password):
        raise ValidationError("Password must contain at least one special character: @$!%*?&.")
    if re.search(r"(password|123456|qwerty|letmein|welcome)", password, re.I):
        raise ValidationError("Password is too common. Please choose a different one.")


class Loginform(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=64)])
    submit = SubmitField('Login')

#cleanup usernames
class SignUpForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=64), password_complexity_check])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    tenant_id = SelectField('Company', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class AddTenantUserForm(FlaskForm):
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=6, message="Password must be at least 6 characters")
    ])
    role = SelectField('Role', choices=[
        ('user', 'User (Standard)'),
        ('admin', 'Admin (Full Access)')
    ], default='user')
    submit = SubmitField('Create User')

class TwoFactorForm(FlaskForm):
    code = StringField('Verification Code', validators=[
        DataRequired(message="Enter 6-digit code"),
        Length(min=6, max=6, message="Code must be 6 digits")
    ])
    submit = SubmitField('Verify')


class CompanySignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    company_region = SelectField('Company Region', choices=[('APAC','APAC'),('EMEA','EMEA')], validators=[DataRequired()])
    company_name = StringField('Company name', validators=[DataRequired(), Length(min=2)])
    company_industry = StringField('Company Industry', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class SecurityBaselineForm(FlaskForm):
    mfa_enabled = BooleanField('Enable MFA')
    dlp_enabled = BooleanField('Enable DLP')
    dlp_monitor_only = BooleanField('Monitor only (Log event, show nothing)')
    dlp_notify_user = BooleanField('Notify user (Show inline warning)')
    dlp_require_approval = BooleanField('Require justification / approval')
    dlp_block_action = BooleanField('Block with explanation')
    dlp_trigger_incident = BooleanField('Trigger incident response')
    data_retention_days = IntegerField('Data Retention (days)', validators=[NumberRange(min=30, max=3650)])
    rls_enabled = BooleanField('Enable RLS (Row Level Security)', default=True)
    submit = SubmitField('Apply Security Baselines')

class TenantRecoveryForm(FlaskForm):
    confirm_recovery = BooleanField('Confirm tenant reactivation', validators=[DataRequired()])
    submit = SubmitField('Reactivate Tenant')



class ForgetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Next')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(max=64), password_complexity_check])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class TenantDeactivateForm(FlaskForm):
    # Compliance confirmation (required)
    compliance_confirm = BooleanField(
        'Confirm compliance data export',
        validators=[DataRequired(message="You must confirm data export")]
    )

    # Retention period
    retention_days = RadioField(
        'Retention after deactivation',
        choices=[
            ('30', '30 days (Recommended)'),
            ('60', '60 days'),
            ('90', '90 days')
        ],
        default='30',
        validators=[DataRequired()]
    )

    # Submit button
    submit = SubmitField('Confirm Deactivation')


class BackupScheduleForm(FlaskForm):
    backup_frequency = SelectField(
        'Frequency',
        choices=[('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')],
        default='daily',
        validators=[DataRequired()]
    )
    backup_time = StringField('Time (HH:MM)', validators=[DataRequired()])
    enable_scheduled = BooleanField('Enable scheduled backups')
    scope_full = BooleanField('Full tenant data', default=True)
    scope_compliance = BooleanField('Compliance metadata only')
    retention_days = IntegerField(
        'Retention (days)',
        default=30,
        validators=[NumberRange(min=1, max=365)]
    )
    save_settings = SubmitField('💾 Save Backup Settings')

# 🔥 FORM 2: Backup + Restore ONLY
class BackupActionForm(FlaskForm):
    restore_step = RadioField(
        'Restore Type',
        choices=[('choose', 'Choose backup'), ('full_restore', 'Full restore'), ('partial_restore', 'Partial restore')],
        default='choose'
    )
    backup_file = FileField(
        'Select backup file',
        validators=[FileAllowed(['sql', 'json', 'zip'], 'Backup files only')]
    )
    backup_submit = SubmitField('💾 Create Backup Now')
    restore_submit = SubmitField('🔄 Start Restore')

from flask import Flask, render_template, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import (StringField, TextAreaField, SelectField, SubmitField, DateField, TimeField, PasswordField, FileField,
                     RadioField, FieldList, FormField, BooleanField)
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, Regexp
from flask_wtf.file import FileAllowed
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
    submit = SubmitField('Sign Up')


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

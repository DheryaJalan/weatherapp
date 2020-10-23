from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from weather.models import User, City

class RegisterationForm(FlaskForm):
    email = StringField('Email Id', validators =[DataRequired(), Email()])
    password = PasswordField('Password', validators =[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
    validators =[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self,email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('This email is already taken.Try another one.')



class LoginForm(FlaskForm):
    email = StringField('Email Id', validators =[DataRequired(), Email()])
    password = PasswordField('Password', validators =[DataRequired()])
    submit = SubmitField('Sign In')

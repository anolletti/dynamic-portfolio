from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (StringField, TextAreaField)
from wtforms.fields import EmailField
from wtforms.validators import InputRequired


class CourseForm(FlaskForm):
    recaptcha = RecaptchaField()

    name = StringField('Name', validators=[InputRequired()
                                           ])
    message = TextAreaField('Message',
                            validators=[InputRequired(),
                                        ])
    email = EmailField('Email Address',
                       validators=[InputRequired()])

from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from app.models import Users, Files, Budget
from app import app

class RegistrationForm(FlaskForm):
    name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=200)])
    # username = StringField('Username',
    #                        validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                           validators=[DataRequired(), Email()])
    
    phone = StringField('Phone',
                           validators=[DataRequired(), Length(min=2, max=200)])
    
    role = StringField('Role',
                           validators=[DataRequired(), Length(min=2, max=200)])
    
    date = StringField('Date',
                           validators=[DataRequired(), Length(min=2, max=200)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email address is taken. Please chose another.')
        
    def validate_phone(self, phone):
        user = Users.query.filter_by(phone=phone.data).first()
        if user:
            raise ValidationError('Phone number is taken. Please chose another.')




class UpdateUserForm(FlaskForm):
    id = IntegerField('Id')
    name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=200)])
    email = StringField('Email',
                           validators=[DataRequired(), Email()])
    
    phone = StringField('Phone',
                           validators=[DataRequired(), Length(min=2, max=200)])
    
    role = StringField('Role',
                           validators=[DataRequired(), Length(min=2, max=200)])
    
    date = StringField('Date',
                           validators=[DataRequired(), Length(min=2, max=200)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Submit')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = Users.query.filter_by(email=email.data).first()
            if user == current_user:
                raise ValidationError('Email address is taken. Please chose another.')
        
    def validate_phone(self, phone):
        if phone.data != current_user.phone:
            user = Users.query.filter_by(phone=phone.data).first()
            if user == current_user:
                raise ValidationError('Phone number is taken. Please chose another.')






class LoginForm(FlaskForm):
    phone = StringField('Phone',
                           validators=[DataRequired(), Length(min=2, max=200)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')




def choice_func_file():
    with app.app_context():
        files = Files.query.all()
        files_list = [(0, "Select File")]
        for file in files:
            fileNo = file.file_no
            # fileId = file.id
            files_list.append((fileNo, fileNo))
    return files_list


def choice_func_budget():
    with app.app_context():
        budgets = Budget.query.all()
        budgets_list = [(0, "Select Budget")]
        for budget in budgets:
            bdgtPurpose = budget.purpose
            bdgtId = budget.id
            bdgtAmnt = str(budget.amount)
            bdgtFig = bdgtPurpose+ ' - ' +bdgtAmnt
            budgets_list.append((bdgtId, bdgtFig))
    return budgets_list


class PayForm(FlaskForm):
    amount = IntegerField('Amount',
                           validators=[DataRequired()])
    
    narration = StringField('Description', validators=[DataRequired(), Length(min=1, max=200)])
    
    paybill = StringField('Paybill', validators=[DataRequired()])

    # file_no = SelectField('Select File', choices=choice_func_file(), validators=[DataRequired()])
    file_no = SelectField('Select File', choices=[], validators=[DataRequired()])

    # budget_no = SelectField('Select Budget', choices=choice_func_budget(), validators=[DataRequired()])
    budget_no = SelectField('Select Budget', choices=[], validators=[DataRequired()])

    submit = SubmitField('Submit')



class FileForm(FlaskForm):

    file_no = StringField('File Number', validators=[DataRequired()])
    file_name = StringField('File Name', validators=[DataRequired()])
    subject = StringField('Subject', validators=[DataRequired()])
    file_fee = IntegerField('File Fees', validators=[DataRequired()])

    submit = SubmitField('Submit')


    


class BudgetForm(FlaskForm):
    # name = StringField('Name',
    #                        validators=[DataRequired(), Length(min=2, max=200)])
    # email = StringField('Email',
    #                        validators=[DataRequired(), Email()])
    
    # phone = StringField('Phone',
    #                        validators=[DataRequired(), Length(min=2, max=200)])
    
    amount = IntegerField('Amount',
                           validators=[DataRequired()])
    
    name = StringField('Name', validators=[DataRequired()])
    
    purpose = StringField('Purpose', validators=[DataRequired()])

    submit = SubmitField('Submit')


from flask import render_template, request, url_for, flash, redirect, abort, session
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, BudgetForm, UpdateUserForm, PayForm, FileForm
from app.models import Users, Budget, Transaction, Payment, Files
from datetime import datetime
from flask_login import login_user, current_user, logout_user, login_required
import uuid
import base64
import json
import requests
import time
from flask_bcrypt import Bcrypt




# def create_db():
#     with app.app_context():
#         db.create_all()


@app.route('/home')
@login_required
def home():
    return render_template('home.html', page='home',)
# ------------------------------------------------------------------------------- #
@app.route('/register', methods=['POST', 'GET'])
def register():
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        date_val = form.date.data
        date_value = datetime.strptime(date_val, "%Y-%m-%d")
        user = Users(name=form.name.data, email=form.email.data, phone=form.phone.data, role=form.role.data, password=hashed_pw, date=date_value)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.name.data}!', 'success')
        return redirect(url_for('users'))
    return render_template('register.html', page='register', title='Register', form=form)

@app.route('/')
@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(phone=form.phone.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'You have been logged in!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash(f'Login Unsuccesseful. Check your details!', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/account/<user_id>')
@login_required
def account(user_id):
    user = Users.query.get_or_404(user_id)
    # if user.phone != current_user:
    #     abort(403)
    return render_template('account.html', page='account', title='Account', user=user)


@app.route('/budgets')
@login_required
def budgets():
    budgets = Budget.query.all()
    return render_template('budgets.html', page='budgets', title='Budgets', budgets=budgets)


@app.route('/approvals')
@login_required
def approvals():
    budgets = Budget.query.order_by(Budget.date.desc()).all()
    return render_template('approvals.html', page='approvals', title='Approvals', budgets=budgets)


@app.route('/new_budget/new', methods=['POST', 'GET'])
@login_required
def create_budget():
    budgets = Budget.query.all()
    form = BudgetForm()
    bdgt_id = str(uuid.uuid4())
    available_funds = 30000
    funds_list = []
    for budget in budgets:
        budget_amount = budget.amount
        funds_list.append(budget_amount)
    budget_funds = sum(funds_list)

    
    if form.validate_on_submit():
        if available_funds > budget_funds + form.amount.data:
            budget = Budget(budget_id=bdgt_id, amount=form.amount.data, bdgt_name=form.name.data, purpose=form.purpose.data, phone=current_user)
            db.session.add(budget)
            db.session.commit()
            flash('Your budget has been created. Await Approval!', 'success')
            return redirect(url_for('budgets'))
        else:
            flash('Insufficient funds. Please top up account!', 'warning')
            return redirect(url_for('create_budget'))
    return render_template('create_budget.html', page='budgets', title='Create New Budget',
                           form=form, legend='New Budget')
    



@app.route("/budget/<int:budget_id>/update", methods=['POST', 'GET'])
def budget(budget_id):
    budget = Budget.query.get_or_404(budget_id)

    # ---------------------------------------------
    transactions = Transaction.query.filter_by(budget=budget_id).all()
    trans_amnt_list = []
    if transactions:
        for trans in transactions:
            trans_amount = trans.amount
            trans_amnt_list.append(trans_amount)
    utilised_funds = sum(trans_amnt_list)
    available_funds = budget.amount - utilised_funds
    # ---------------------------------------------

    purposeEditVal = json.loads(budget.purpose)
    urls = request.path
    urls = urls.split('/')
    urls = urls[-1]
    if budget.phone != current_user:
        abort(403)
    form = BudgetForm()
    if form.validate_on_submit():
        if budget.status == 1:
            flash('Your budget is Approved. You cannot Update!', 'warning')
            return redirect(url_for('budgets'))
        else:
            budget.amount = form.amount.data
            budget.purpose = form.purpose.data
            budget.bdgt_name = form.name.data
            budget.status = 0
            db.session.commit()
            flash('Your budget has been Updated. Await Approval!', 'success')
            return redirect(url_for('budgets'))
    elif request.method == 'GET':
        form.amount.data = budget.amount
        form.purpose.data = budget.purpose
        form.name.data = budget.bdgt_name
    return render_template('create_budget.html', page='budgets', title='Update Budget', available_funds=available_funds, budget=budget, edit_vals=purposeEditVal, url=urls, ad_class = 'disabled', form=form, del_id=budget.id, phone=budget.phone, legend='Update Budget',
                           delete_bdgt='<a role="button" class="btn btn-outline-danger btn-sm" data-toggle="modal" data-target="#deleteModal">Delete Budget</a>')



@app.route("/user/<int:user_id>/update", methods=['POST', 'GET'])
def user(user_id):
    user = Users.query.get_or_404(user_id)
    
    form = UpdateUserForm()
    if form.validate_on_submit():

        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        date_val = form.date.data
        date_value = datetime.strptime(date_val, "%Y-%m-%d")

        user.name = form.name.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.role = form.role.data
        if user == current_user:
            user.password = hashed_pw

        user.date = date_value

        db.session.commit()
        flash('User has been Updated!', 'success')
        return redirect(url_for('account', user_id=user.id))
    elif request.method == 'GET':
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.role.data = user.role
        form.id.data = user.id
        form.date.data = user.date.strftime('%Y-%m-%d')
    return render_template('register.html', page='users', title='Update user', form=form, del_id=user.id, user=user, legend='Update user')


@app.route("/budget/<int:budget_id>/delete", methods=['POST'])
def delete_budget(budget_id):
    budget = Budget.query.get_or_404(budget_id)
    if budget.phone != current_user:
        abort(403)
    db.session.delete(budget)
    db.session.commit()
    flash('Your budget has been Deleted!', 'success')
    return redirect(url_for('budgets'))


@app.route("/user/<int:user_id>/delete", methods=['POST'])
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)
    if current_user.role != 'Admin':
        abort(403)
    db.session.delete(user)
    db.session.commit()
    flash('User has been Deleted!', 'success')
    return redirect(url_for('users'))


@app.route('/new_file/new', methods=['POST', 'GET'])
@login_required
def create_file():
    files = Files.query.all()

    form = FileForm()
    if form.validate_on_submit():
        file = Files(file_no=form.file_no.data, file_name=form.file_name.data, subject=form.subject.data, file_fee=form.file_fee.data)
        db.session.add(file)
        db.session.commit()
        flash('File created successfuly!', 'success')
        return redirect(url_for('files'))
    elif request.method == 'GET':
        if len(files) == 0:
            form.file_no.data = '100/1/C'
        elif len(files) > 0:
            file_list = []
            def_val = 0
            for file in files:
                val = file.file_no
                val = val.split('/')
                no_val = val[0]
                file_list.append(no_val)
            initial_val = int(max(file_list))+1
            def_val = str(initial_val)+'/1/C'
            form.file_no.data = def_val
            # print(word.split(', ', 1))
    return render_template('create_file.html', page='files', title='Create New file',
                           form=form, legend='New File')


@app.errorhandler(404)
def error_404(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(403)
def error_403(error):
    return render_template('errors/403.html'), 403


@app.errorhandler(500)
def error_500(error):
    return render_template('errors/500.html'), 500
# ------------------------------------------------------------------------------- #

# @app.route('/create')
# def create_all():
#     # return 'Hello World!'
#     create_db()

#     return 'ok'


@app.route('/transactions')
@login_required
def transactions():

    if current_user.role == 'Admin':
        transactions = Transaction.query.all()
    else:
        transactions = Transaction.query.filter_by(user_id=current_user.id).all()

    return render_template('transactions.html', page='transactions', transactions=transactions)


@app.route('/files')
@login_required
def files():
    
    files = Files.query.all()
    if len(files) == 0:
        count = 0
    else:
        count = len(files)

    return render_template('files.html', page='files', files=files, count=count)


# @app.route("/transactions/<string:transaction_id>/delete", methods=['POST'])
# def delete_transaction(transaction_id):
#     transaction = Transaction.query.get_or_404(transaction_id)
#     if current_user.role != 'Admin':
#         abort(403)
#     db.session.delete(transaction)
#     db.session.commit()
#     flash('Record has been Deleted!', 'success')
#     return redirect(url_for('transactions'))


# @app.route('/approvals', methods=['POST', 'GET'])
# @login_required
# def approvals():
#     return render_template('approvals.html', page='approvals', data=approvals_table_content)


# @app.route('/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
# def users():
#     if request.method == 'GET':
#         users = Users.query.all()
#         return render_template('users.html', users=users)
#     elif request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         phone = "254"+request.form['phone']
#         role = request.form['role']
#         password = request.form['password']
#         date = datetime.today().strftime('%d-%m-%Y')

#         if name == '' or email == '' or phone == '' or role == '' or password == '':
#             return render_template('users.html', message='Please enter required fields.') 
        
#         data = Users(name, email, phone, role, password, date)
#         db.session.add(data)
#         db.session.commit()
#         return render_template('users.html', message='User added successfully.')
        # return redirect("/users")



@app.route("/users")
def users():
    users = Users.query.all()
    return render_template('users.html', page='users', users=users)





@app.route('/payment_request', methods=['POST', 'GET'])
@login_required
def payment_request():
    # files = Files.query.all()
    form = PayForm()
    budgets_list = [(0, "Select Budget")]
    budgets = Budget.query.all()
    for budget in budgets:
        bdgtPurpose = budget.bdgt_name
        bdgtId = budget.id
        bdgtAmnt = str(budget.amount)
        bdgtFig = bdgtPurpose+ ' - ' +bdgtAmnt
        budgets_list.append((bdgtId, bdgtFig))
    form.budget_no.choices = budgets_list
    
    files = Files.query.all()
    files_list = [(0, "Select File")]
    for file in files:
        fileNo = file.file_no
        fileName = file.file_name
        full_desc = fileNo+ ' - ' +fileName
        files_list.append((fileNo, full_desc))
    form.file_no.choices = files_list

    if form.validate_on_submit():
        # Payment variables
        amount = form.amount.data
        narration = str(form.narration.data)
        partyB = form.paybill.data
        file = str(form.file_no.data)
        budgetId = form.budget_no.data
        print(budgetId)

        # -----------------------------------------------------------------------------
        budget = Budget.query.get_or_404(budgetId)
        transactions = Transaction.query.filter_by(budget=budgetId).all()
        trans_amnt_list = []
        if transactions:
            for trans in transactions:
                trans_amount = trans.amount
                trans_amnt_list.append(trans_amount)
        utilised_funds = sum(trans_amnt_list)
        available_funds = budget.amount - utilised_funds


        print(utilised_funds)
        print(available_funds)
        print(amount)
        print(narration)


        if amount > available_funds:
            flash('Insufficient funds for this transaction!  Avalilable funds - '+str(available_funds)+'', 'warning')
            return redirect(url_for('transactions'))
        # -----------------------------------------------------------------------------


        
        session["budgetId"] = budgetId
        session["fileId"] = file
        session["descr"] = narration

        
    
        token = generate_access_token()

        initiator_pass = "Safaricom999!*!"
        public_key = "-----BEGIN CERTIFICATE-----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-----END CERTIFICATE-----"
        security_credential = base64.b64encode((initiator_pass + public_key).encode('utf-8')).decode()
        # securityCredential = "FkNWT9e5UOQPvs3fDqmZQ0sQn9gjQtlyn71IVqSeSzFjSarWJ1sPZHXzxQrquzPbaTTEeoWaB0D7rNfhgOqyash1n74qIhmNE4JsUC1IExWABY2risn7uzxPA2DToE1lVnV9EJAOvaq0uWlMhRnmInTS21samw2OGISATYkPmqVDIiTjEsyFjZNkdF996YYXGpocYKD437SuRVSGPQWdf5/ZauojPLiCXoFkmKVTayU2Dg+3yFszLlSyQ0ceVZACqFPGeJDTLNHG76y54bzvDLXbT1NZIezTl2mW3sbtTh0jvIUVKnyfD2oEXMNzz+jHugi/iShla0JeIJZRhwh1IQ=="
        securityCredential = "ZdWTIszTXMkF07d8tPQKxwLYSqBhWODLzu66+m5uXBgdg8mGmUQRVjjdo16KqRKKpwl5SLzjTzyLBKncYHew2iuSZzBeBzG4k7U7g8SO+ThizuM7UvFSHTj0AchQqBRppcFcYFnIo8t+QmfNfnqbsYGnT/nd0biR7Cn1G8w1UE7kTYBsY5TkB4WzmleByvyzGMpiz9UQHGIv9q3yrKmdH3+Akw80u8ibMriN1iyQFORILZvpA7pfsjr0VIC9sV0hFh632fuskT4biklhn4CbOCmpAkfCe90mf2GEUCsQBjLJ1WR1ewFuLPiJvxPEsywv5Kr9q8vRmlEMoQXDcaqhEw=="

        url = 'https://sandbox.safaricom.co.ke/mpesa/b2b/v1/paymentrequest'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer %s' % token
        }
        payload = {
            "Initiator": "testapi",
            "SecurityCredential": securityCredential,
            "CommandID": "BusinessPayBill",
            "SenderIdentifierType": "4",
            "RecieverIdentifierType": 4,
            "Amount": amount,
            "PartyA": 600997,
            "PartyB": partyB,
            "AccountReference": "353353",
            "Requester": "254700000000",
            "Remarks": "OK",
            "QueueTimeOutURL": "https://budgetfiles.onrender.com/callback",
            "ResultURL": "https://budgetfiles.onrender.com/callback"
        }

        try:
            response = requests.request("POST", url, headers = headers, json = payload).json()
            if response['ResponseCode'] == '0':
                # return response
                data = dict()
                data['amount'] = amount
                data['paybill']   = partyB
                data['file_no']   = file
                return render_template('pay.html', resp_details=response, resp_data=data)
            else:
                flash('Transaction Failed!.', 'danger')
                return redirect(url_for('transactions'))
        except Exception as e:
            print('Error:', str(e))

    

    return render_template('payment_request.html', title='Request New Payment',
                           form=form, legend='New Payment')



















@app.route('/budget/<int:budget_id>/view', methods=['GET'])
def view_budget(budget_id):
        
    budget = Budget.query.get_or_404(budget_id)
    budget_ppse = json.loads(budget.purpose)

    return render_template('confirm_budget.html', budget=budget, budget_ppse=budget_ppse, page='approvals', title='Confirm Budget', user=user)




@app.route('/approvals/<int:budget_id>/confirm_budget/<string:approve_string>', methods=['POST', 'GET'])
def approve_budget(budget_id, approve_string):
        
    budget = Budget.query.get_or_404(budget_id)
    if approve_string == 'approve':
        budget.status = 1
        budget.approved_by = current_user.name
        db.session.commit()
        flash('Budget has been Approved!', 'success')
        return redirect(url_for('approvals'))
    elif approve_string == 'disapprove':
        budget.status = 2
        budget.approved_by = current_user.name
        db.session.commit()
        flash('Budget has been Dispproved!', 'danger')
        return redirect(url_for('approvals'))

    # return render_template('confirm_budget.html', budget=budget, page='approvals', title='Confirm Budget', user=user)








    
    






@app.route("/callback", methods=["POST"])
def handle_callback():
    json_repsonse = request.get_json()
    result = json_repsonse["Result"]

    # --------------- Write to file ------------------------------------------------------------
    msg = json_repsonse

    with open("callbackfile.json", "a") as f:
        json.dump(msg, f)
    # ---------------------------------------------------------------------------
    
    status = result['ResultCode']
    if status == 0:
        mpesa_ref = result["TransactionID"]
        merchant_req_id = result['ConversationID']
        date_values = str(result['ResultParameters']['ResultParameter'][3]['Value'])

        date_val = date_values[0:4]+"-"+date_values[4:6]+"-"+date_values[6:8]+" "+date_values[8:10]+":"+date_values[10:12]+":"+date_values[12:14]
        trans_date = datetime.strptime(date_val, "%Y-%m-%d %H:%M:%S")

        amount = result['ResultParameters']['ResultParameter'][5]['Value']
        transaction_id = str(uuid.uuid4())
        user_id = 1
        budget = 0
        file = '-'
        narration = '-'

        trans = Transaction(transaction_id=transaction_id, mpesa_ref=mpesa_ref, merchant_req_id=merchant_req_id, trans_date=trans_date, status=status, amount=amount, user_id=user_id, budget=budget, file=file, narration=narration)
        db.session.add(trans)
        db.session.commit()
        
        return mpesa_ref
    else:
        msg = result['ResultDesc']

        with open("callbackfile.json", "a") as f:
            json.dump(msg, f)
        flash(msg, 'success')
        return redirect("/transactions")




def the_callback(resp):
    status = resp['ResultCode']

    msg = resp['ResultDesc']

    with open("callbackfile.json", "a") as f:
        json.dump(msg+" "+str(status), f)

    return 0


def the_redirect():
    return redirect("/transactions")






# Confirm Payment
# @app.route("/pay/<string:merchant_req_id>/confirm_payment", methods=['POST'])
# def confirm_payment(merchant_req_id):
#     # payment = Transaction.query.get_or_404(merchant_req_id)
#     payment = Transaction.query.filter_by(merchant_req_id=merchant_req_id).first()
#     if payment:
#         payment.user_id = current_user.id
#         db.session.commit()
#         flash('Your payment with Mpesa ref:  '+payment.mpesa_ref+ '  was Successful.', 'success')
#         return redirect(url_for('transactions'))
#     else:
#         flash('Your payment with REQUEST ID:  '+merchant_req_id+ '  was NOT Successful.', 'danger')
#         return redirect(url_for('transactions'))
        






# Confirm Payment
@app.route("/pay/<string:merchant_req_id>/confirm_payment", methods=['POST'])
def confirm_payment(merchant_req_id):
    wait = 1
    count = 0

    while count < 5:
        time.sleep(wait)
        # payment = Transaction.query.get_or_404(merchant_req_id)
        payment = Transaction.query.filter_by(merchant_req_id=merchant_req_id).first()
        if payment:
            count = 5
            budget = session.get("budgetId", None)
            fileNo = session.get("fileId", None)
            description = session.get("descr", None)
            payment.user_id = current_user.id
            payment.budget = budget
            payment.file = fileNo
            payment.narration = description
            
            db.session.commit()
            if payment.status == '0':
                flash('Your payment with Mpesa ref:  '+payment.mpesa_ref+ '  was Successful', 'success')
                return redirect(url_for('transactions'))
            else:
                flash('Your payment with REQUEST ID:  '+merchant_req_id+ '  was NOT Successful.', 'danger')
                return redirect(url_for('transactions'))
        else:
            count+=1

    else:
        flash('Your payment with REQUEST ID:  '+merchant_req_id+ '  was NOT Successful.', 'danger')
        return redirect(url_for('transactions'))








# @app.route('/users/<user_id>', methods=['PUT'])
# def edit_user(user_id):
#     user_id = request.form['edit_user_id']
#     data = Users.query.filter_by(id==id).first()
#     data = Users(name, email, phone, role, password, date)
#     db.session.add(data)
#     db.session.commit()

# @app.route('/submit', methods=['POST', 'GET'])
# def submit_user():
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         phone = request.form['phone']
#         role = request.form['role']
#         password = request.form['password']
#         date = datetime.today().strftime('%d-%m-%Y')

#         if name == '' or email == '' or phone == '' or role == '' or password == '':
#             return render_template('users.html', message='Please enter required fields.') 
        
#         data = Users(name, email, phone, role, password, date)
#         db.session.add(data)
#         db.session.commit()
#         # return render_template('success.html')
#         return render_template('users.html', message='User added successfully.')
#         # return redirect("/users")
#     elif request.method == 'GET':
#         users = Users.query.all()
#         return render_template('users.html', users=users)



# @app.route('/submit', methods=['POST'])
# def submit():
#     if request.method == 'POST':
#         customer = request.form['customer']
#         dealer = request.form['dealer']
#         rating = request.form['rating']
#         comments = request.form['comments']
#         # print(customer, dealer, rating, comments)
#         if customer == '' or dealer == '':
#             return render_template('index.html', message='Please enter required fields.') 
#         if db.session.query(Feedback).filter(Feedback.customer == customer).count() == 0:
#             data = Feedback(customer, dealer, rating, comments)
#             db.session.add(data)
#             db.session.commit()
#             return render_template('success.html')
#         return render_template('index.html', message='Hello '+customer+', you have already submitted feedback.')
    

def generate_access_token():
    consumer_key = "XZSPT4CIhfvAhRPdfq6EIkP1zcfHOFGigSb3fjueD4AKFKQO"
    consumer_secret = "jr04RpkXcvJsJwUHA3MMdgxS7lxwNyMiHujPOTpdOaGGGCLOIhyszxIDnDFL23bZ"

    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

    try:

        encoded_credentials = base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()


        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json"
        }

        # Send the request and parse the response
        response = requests.request("GET", url, headers=headers).json()

        # Check for errors and return the access token
        if "access_token" in response:
            return response["access_token"]
        else:
            raise Exception("Failed to get access token: " + response["error_description"])
    except Exception as e:
        raise Exception("Failed to get access token: " + str(e))
    








#  Delete all records in transactions table.
# @app.route("/del", methods=['POST', 'DELETE', 'GET'])
# def delete_rec():
#     from app import app, db
#     from datetime import datetime
#     bcrypt = Bcrypt()
#     date_val =  '2024-6-12'
#     date_value = datetime.strptime(date_val, "%Y-%m-%d")
#     with app.app_context():
#         db.drop_all()
#         db.create_all()
#         from app.models import Users, Budget
#         user1 = Users(name='John Doe', email='jon@gmail.com', phone='254722345678', role='Admin', password=bcrypt.generate_password_hash('123').decode('utf-8'), date=date_value)
#         user2 = Users(name='New User', email='new@gmail.com', phone='254742345678', role='Staff', password=bcrypt.generate_password_hash('123').decode('utf-8'), date=date_value)
#         user3 = Users(name='Pat Jenkins', email='pat@gmail.com', phone='254712345678', role='Admin', password=bcrypt.generate_password_hash('123').decode('utf-8'), date=date_value)
#         db.session.add(user1)
#         db.session.add(user2)
#         db.session.add(user3)
#         db.session.commit()
#     flash('Your Record has been Deleted!', 'success')
#     return redirect(url_for('budgets'))



@app.route("/del", methods=['POST', 'DELETE', 'GET'])
def delete_rec():

    # transactions = Transaction.query.all()
    db.session.query(Transaction).delete()
    db.session.commit()

    flash('Your Record has been Deleted!', 'success')
    return redirect(url_for('budgets'))
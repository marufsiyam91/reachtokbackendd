from flask import Flask, request, session, redirect, jsonify
from datetime import datetime, timedelta
import os
import pymongo
import bcrypt
from flask_cors import CORS
import stripe

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default-secret-key")
CORS(app)

# Stripe API setup
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# MongoDB connection
def MongoDB():
    mongo_uri = os.getenv("MONGODB_URI")
    client = pymongo.MongoClient(mongo_uri)
    db = client.get_database('total_records')
    records = db.register
    payments = db.payments  # Payment records
    return records, payments

records, payments = MongoDB()

@app.route("/", methods=['POST'])
def index():
    if "email" in session:
        return jsonify({"redirect": "/logged_in"})
    
    data = request.json
    user = data.get("fullname")
    email = data.get("email")
    password1 = data.get("password1")
    password2 = data.get("password2")
    
    user_found = records.find_one({"name": user})
    email_found = records.find_one({"email": email})

    if user_found:
        return jsonify({"message": "There already is a user by that name"}), 400
    if email_found:
        return jsonify({"message": "This email already exists in the database"}), 400
    if password1 != password2:
        return jsonify({"message": "Passwords should match!"}), 400
    else:
        hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
        user_input = {'name': user, 'email': email, 'password': hashed}
        records.insert_one(user_input)
        user_data = records.find_one({"email": email})
        new_email = user_data['email']
        session["email"] = new_email
        return jsonify({"redirect": "/logged_in"}), 201

@app.route("/login", methods=["POST"])
def login():
    if "email" in session:
        return jsonify({"redirect": "/logged_in"})

    data = request.json
    email = data.get("email")
    password = data.get("password")

    email_found = records.find_one({"email": email})
    if email_found:
        email_val = email_found['email']
        passwordcheck = email_found['password']
        
        if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
            session["email"] = email_val
            return jsonify({"redirect": "/logged_in"})
        else:
            return jsonify({"message": "Wrong password"}), 400
    else:
        return jsonify({"message": "Email not found"}), 400

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return jsonify({"email": email})
    else:
        return jsonify({"redirect": "/login"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return jsonify({"redirect": "/"})
    else:
        return jsonify({"redirect": "/"}), 401

@app.route('/subscribe', methods=['POST'])
def subscribe():
    current_time = datetime.now().strftime("%d-%m-%Y")
    future_time = datetime.now() + timedelta(days=30)
    return jsonify({
        "message1": "You are subscribed",
        "message": f"Subscribe date is {current_time}",
        "message2": f"Expiry date is {future_time.strftime('%d-%m-%Y')}"
    })

# Payment processing route
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        data = request.json
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': data['product_name'],
                    },
                    'unit_amount': data['amount'],  # Amount in cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=os.getenv('SUCCESS_URL', 'http://localhost:3000/success'),
            cancel_url=os.getenv('CANCEL_URL', 'http://localhost:3000/cancel'),
        )
        return jsonify({'id': session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

# Webhook to handle payment confirmation from Stripe
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    
    event = None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError:
        return jsonify({'status': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'status': 'Invalid signature'}), 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']

        payments.insert_one({
            'email': session['customer_details']['email'],
            'amount': session['amount_total'] / 100,  # Convert cents to dollars
            'currency': session['currency'],
            'payment_status': session['payment_status'],
            'created_at': datetime.now(),
            'product_name': session['display_items'][0]['custom']['name']
        })

    return jsonify({'status': 'success'}), 200

# Customer payment history
@app.route('/customer/payments', methods=['GET'])
def customer_payments():
    if "email" in session:
        email = session["email"]
        user_payments = payments.find({"email": email})
        payments_list = []
        for payment in user_payments:
            payments_list.append({
                "amount": payment["amount"],
                "currency": payment["currency"],
                "status": payment["payment_status"],
                "product_name": payment["product_name"],
                "created_at": payment["created_at"].strftime("%d-%m-%Y")
            })
        return jsonify(payments_list)
    else:
        return jsonify({"redirect": "/login"}), 401

# Admin view all payments
@app.route('/admin/payments', methods=['GET'])
def admin_payments():
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    if "email" in session and session["email"] == admin_email:
        all_payments = payments.find({})
        payments_list = []
        for payment in all_payments:
            payments_list.append({
                "email": payment["email"],
                "amount": payment["amount"],
                "currency": payment["currency"],
                "status": payment["payment_status"],
                "product_name": payment["product_name"],
                "created_at": payment["created_at"].strftime("%d-%m-%Y")
            })
        return jsonify(payments_list)
    else:
        return jsonify({"message": "Unauthorized"}), 401

UPLOAD_FOLDER = 'uploaded_videos'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/video', methods=['POST'])
def video():
    if 'video' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['video']
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    
    if file:
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(save_path)
        return jsonify({"message": f"Video saved to {save_path}"}), 201

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))

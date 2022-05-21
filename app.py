from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
import os

# Keras
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
Bootstrap(app)

db = SQLAlchemy(app)
admin = Admin(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

BASE_PATH = os.getcwd() #returns current directory of the process
UPLOAD_PATH = os.path.join(BASE_PATH, 'static/upload')


# Model saved with keras model.save()
MODEL_PATH = 'static/model/blood_cancer_detection.h5'

# loading train model

model = load_model(MODEL_PATH) #previously load model can be used with same functionality


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)



class Controller(ModelView):
    def is_accessible(self):
        if current_user.is_admin == True:
            return current_user.is_authenticated
        else:
            return abort(404)

        # return current_user.is_authenticated

    def not_aut(self):
        return "you are not authorized to use the admin panel"

admin.add_view(Controller(User, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## login and register
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')



class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    

@app.route('/')
def index():     # function
    return render_template('index.html') 

@app.route('/create_admin', methods=['POST', 'GET'])
def create_admin():
    form = LoginForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password, is_admin=True)
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('upload'))
    return render_template('admin_signup.html', form=form)
    

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash('You have been logged in!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        # return '<h1>' + form.email.data + ' ' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('register.html', form=form)




# pipline of model
def model_predict(img_path, model):
    img = image.load_img(img_path, target_size=(150,150))

    # Preprocessing the imgae
    x = image.img_to_array(img)

    ## Scaling
    x = x/255
    x = np.expand_dims(x, axis=0)
    images = np.vstack([x])
    predict_x = model.predict(images, batch_size=10)
    preds = np.argmax(predict_x, axis=1)
    if preds ==[1]:
        preds = " You have cancer"
    elif preds == [0]:
        preds= "You don't have cancer"
    else:
        preds("Sorry. The image is not valid.")

    return preds

@app.route('/upload', methods=['POST', 'GET'])
@login_required
def upload():
    if request.method == 'POST':
        uploaded_file = request.files['image_name']
        filename = uploaded_file.filename
        print('The filename that has been uploaded =', filename)

        ext = filename.split('.')[-1]
        print('The extension of the filename =', ext)
        if ext.lower() in ['png', 'jpg', 'jpeg']:
            path_save = os.path.join(UPLOAD_PATH, filename)
            uploaded_file.save(path_save)
            # flash('Successfully uploaded')
            preds = model_predict(path_save, model)
            result = preds
            flash( result)
        
        else:
            flash('Use only the extension with .jpg, .png, jpeg')
       
    
    return render_template('upload.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask,render_template,request
from flask.helpers import flash
from werkzeug.utils import redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager,login_user,login_required,current_user,logout_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config["SECRET_KEY"] = "mysecretkey"
db = SQLAlchemy(app)

login_manager = LoginManager ()
login_manager.login_view = "login"
login_manager.init_app(app)
class Users (UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column (db.String(200),nullable=False)
    pasword = db.Column(db.String(200),nullable=False)


@login_manager.user_loader
def load_user (user_id):
    return Users.query.get(int(user_id))
@app.route('/')
def Home():
   return render_template("index.html")


@app.route('/signup',methods=['POST','GET'])
def signup():
    if request.method == 'POST':
        name= request.form['name']
        email=request.form['email']
        pasword = request.form['password']
        user = Users.query.filter_by(email=email).first ()
        if user:
            flash("email already exists")
            return redirect('/signup')
        else:
            new_user = Users(name=name,email=email,pasword = generate_password_hash(pasword,method="sha256"))
            try:
                db.session.add(new_user)
                db.session.commit ()
                return redirect('/login')
            except:
                return "There was a problem in registering the user"

    else:
        return render_template('signup.html')
@app.route('/login',methods=['POST','GET'])
def login():
    if request.method == "POST":
        email=request.form['email']
        pasword = request.form['password']
        user = Users.query.filter_by(email=email).first ()
        if not user:
            flash("email does not exist")
            return redirect ('/login')
        elif not check_password_hash(user.pasword,pasword):
            flash("Please enter the correct password")
            return redirect ('/login')
        else:
            login_user(user)
            return redirect('/profile')
    else:
        return render_template ("login.html")

@app.route('/profile')
@login_required
def profile():
   return render_template('profile.html',name=current_user.name)

@app.route('/logout')
@login_required
def method_name():
  logout_user()
  return redirect('/')
if __name__ == "__main__":
    app.run(debug=True)
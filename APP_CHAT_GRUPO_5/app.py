from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_session import Session


#CONFIGURACION:________________
app = Flask(__name__)
app.config['SECRET_KEY'] = 'FHBF64BJK866'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
Session(app)
socketio = SocketIO(app, manage_session=False, cors_allowed_origins="*")

#MODELOS:_______________________
class User(UserMixin, db.Model):
    __tablename__="USUARIOS"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#FORMULARIOS:___________________
class LoginForm(FlaskForm):
    username = StringField('usuario', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('contraseña', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('recuerdame')

class RegisterForm(FlaskForm):
    email = StringField('correo electronico', validators=[InputRequired(), Email(message='email invalido'), Length(max=50)])
    username = StringField('usuario', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('contraseña', validators=[InputRequired(), Length(min=8, max=80)])

#VISTAS:_________________________
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        flash('Usuario o Contraseña incorrectos, ó Usuario no registrado')
       # return '<h1>Usuario o Contraseña incorrectos, ó Usuario no registrado</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        email=form.email.data
        user = User.query.filter_by(email=email).first()
        if not user:
            db.session.add(new_user)
            db.session.commit()
            flash("Registro Exitoso...")
        flash("Email ya existe en la base de datos...")

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
    
#CHAT________________
#iniciat chat
@login_required
@app.route('/inicio/chat', methods=['GET', 'POST'])
def inicio_chat():
    return render_template('inicio_chat.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    
    username = current_user.username
    room = "MisionTic 2022"
        
    session['username'] = username
    session['room'] = room
    return render_template('chat.html', session = session)
    #else:
    if(session.get('username') is not None):
        return render_template('chat.html', session = session)
    else:
        return redirect(url_for('index'))

   
#indicar quienes ingresan al chat
@socketio.on('join', namespace='/chat')
def join(message):
    room = session.get('room')
    join_room(room)
    emit('status', {'msg':  session.get('username') + ' Inicio sesion.'}, room=room)

#agregar los mesajes enviados
@socketio.on('text', namespace='/chat')
def text(message):
    room = session.get('room')
    emit('message', {'msg': session.get('username') + ' : ' + message['msg']}, room=room)

#quienes salen del chat
@socketio.on('left', namespace='/chat')
def left(message):
    room = session.get('room')
    username = session.get('username')
    leave_room(room)
    session.clear()
    emit('status', {'msg': username + ' Salio del chat.'}, room=room)


#INICIAR APP:___________________
if __name__ == '__main__':
    app.run(debug=True)

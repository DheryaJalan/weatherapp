from flask import render_template, request, redirect, url_for, flash
from weather import app, db, bcrypt
from weather.models import User, City
import json
import requests
from weather.form import RegisterationForm, LoginForm
from flask_login import login_user, current_user, logout_user, login_required

def weather_data(city):
    url = f'http://api.openweathermap.org/data/2.5/weather?q={ city }&units=metric&appid=de54f4134836f1889b083c8d182aad9e'
    r = requests.get(url).json()
    return r

@app.route('/')
def index_get():
    weather_lst = []
    cities = City.query.all()
    for city in cities:
        s = weather_data(city.name)
        lat = str(s['coord']['lat'])
        lon = str(s['coord']['lon'])
        temperature = int(s['main']['temp'])
        description = s['weather'][0]['description']
        icon = s['weather'][0]['icon']
        serviurl = 'http://api.openweathermap.org/data/2.5/uvi?appid=de54f4134836f1889b083c8d182aad9e&lat={}&lon={}'
        l = requests.get(serviurl.format(lat,lon)).json()
        weather = {
        'city': city.name,
        'temperature' : temperature,
        'uv': float(l['value']),
        'description': description,
        'icon': icon
        }
        weather_lst.append(weather)
    return render_template('home.html',weather_lst=weather_lst)

@app.route('/', methods=['POST'])
@login_required
def index_post():
    error_message=''
    new_city = request.form.get('city')
    if new_city:
        new_city_data = weather_data(new_city)
        old_city = City.query.filter_by(name=new_city).first()
        if old_city:
            error_message = 'City already exists'
        else :
            if new_city_data['cod'] == 200:
                new_city_obj = City(name=new_city)
                db.session.add(new_city_obj)
                db.session.commit()
            else:
                error_message = 'No such sity exists. Check spelling.'
    if error_message:
        flash(error_message,'error')
    else:
        flash('City successfully added!','success')
    return redirect(url_for('index_get'))

@app.route('/delete/<name>')
def delete_city(name):
    city = City.query.filter_by(name=name).first()
    db.session.delete(city)
    db.session.commit()
    flash(f'Successfully deleted {city.name}', 'success')
    return redirect(url_for('index_get'))

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash(f'Successfully added {form.email.data}', 'success')
        return redirect(url_for('login'))
    else:
        flash('Registeration unsuccessfull. Please check your email and password.')
    return render_template('register.html', title = 'Registeration', form=form)



@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated :
        return redirect(url_for('index_post'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Successfully logged in', 'success')
            return redirect(url_for('index_post'))
        else:
            flash('Login unsuccessfull. Please check your email and password', 'danger')
    return render_template('login.html', title = 'Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index_post'))

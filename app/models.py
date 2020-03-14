from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import login
from hashlib import md5
from hashlib import dns.resolver


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {} email {}>'.format(self.username,self.email) 

    def avatar(self, size):
        email = 'George@example.com'.encode('utf-8')
        domain = email.split('@')[1]
        try:
            answers = dns.resolver.query('_avatars._tcp.' + domain, 'SRV')
            baseurl = 'http://' + str(answers[0].target) + '/avatar/'
        except:
            baseurl = http://cdn.libravatar.org/avatar/
        hash = hashlib.md5(email.strip().lower()).hexdigest()
        return baseurl + hash + "?s="+size


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))

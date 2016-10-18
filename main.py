#Front Page that lists entries
# Form to submit new entries
# Permalink page for entries

import os
import webapp2
import re
import jinja2
import random
import hashlib
import hmac
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
															 autoescape = True)

secret = '8fd1b9497d14241f7045f8580e416b25'

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())	

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

## user registration
def make_salt(length = 5):
		return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s, %s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = name = db.StringProperty(required = True)
	email = name = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		user = User.all().filter('name =', name).get()
		return user

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
								name = name,
								pw_hash = pw_hash,
								email = email)

	@classmethod
	def login(cls, name, pw):
		user = cls.by_name(name)
		if user and valid_pw(name, pw, user.pw_hash):
			return user


def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

class MainPage(Handler):
	def get(self):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 8")
		self.render('front.html', posts = posts)

class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post = post)

class NewPost(Handler):
	def get(self):
		self.render("new_post.html")

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			self.redirect('/%s' % str(p.key().id()))

		else:
			error = "You need a subject and content to post a new entry."
			self.render("new_post.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignUp(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		has_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.password_conf = self.request.get('password_conf')
		self.email = self.request.get('email')

		params = dict(username = self.username,
									email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "Please enter a valid username"
			has_error = True

		if not valid_password(self.password):
			params['error_password'] = "Please enter a valid password"
			has_error = True
		elif self.password != self.password_conf:
			params['error_password_conf'] = "Your passwords don't match"
			has_error = True

		if not valid_email(self.email):
			params['error_email'] = "Please enter a valid email address"
			has_error = True

		if has_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self):
		user = User.by_name(self.username)
		if user:
			msg = "That username already exists"
			self.render('signup.html', error_username = msg)
		else:
			user = User.register(self.username, self.password, self.email)
			user.put()

			self.login(user)
			self.redirect('/')

class Register(SignUp):
	def done(self):
		user = User.by_name(self.username)
		if user:
			msg = "That username already exists"
			self.render('signup.html', error_username = msg)
		else:
			user = User.register(self.username, self.password, self.email)
			user.put()

			self.login(user)
			self.redirect('/')

class Login(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		user = User.login(username, password)
		if user:
			self.login(user)
			self.redirect('/')
		else:
			msg = "Invalid login"
			self.render('login.html', error = msg)

class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/([0-9]+)', PostPage),
    ('/newpost', NewPost),
    ('/signup', SignUp),
    ('/login', Login),
    ('/logout', Logout),
		],
		debug=True)
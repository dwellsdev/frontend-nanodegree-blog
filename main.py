import os
import re
from string import letters

import webapp2
import jinja2
import hashlib
import hmac
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
"""
Secret for making good hashes.
"""

SECRET = 'vnri48b484VN49bn#$%9023^9b94V#@#T^22'

"""
Salt for storing better hashed passwords.
"""

def make_salt():
    return ''.join(random.choice(letters) for x in xrange(5))

"""
Generate the hash.
"""

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

"""
Make secure values.
"""
def make_secure_val(s):
    return '%s|%s' % (s, hash_str(s))

"""
Verify secured values.
"""
def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

"""
Helper function to render Jinja2 templates.
"""
def jinja_render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

"""
Here we actually make the password hash.
"""
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

"""
Check if the password is valid...
"""
def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

"""
Regular expression and accompanying to check user ids...
"""
USER_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_REGEX.match(username)

"""
And passwords...
"""

PASS_REGEX = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_REGEX.match(password)

"""
And emails.
"""
EMAIL_REGEX = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_REGEX.match(email)

"""
Handy handler function. (Thanks spez!)
"""

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

        """
        Only thing modified from spez's handler functions.
        Added the params thing to pass user info to the templates.
        """
    def render_str(self, template, **params):
        params['user'] = self.user
        return jinja_render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

        """
        Setting secure cookies.
        """
    def set_secure_cookie(self, name, s):
        cookie_val = make_secure_val(s)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

        """
        Reading secure cookies.
        """
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

        """
        Set the user cookie when logging in...
        """
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

        """
        and clearing it when we log out.
        """
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

        """
        Wiping the slate clean.
        """
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

"""
Renders the post. Added HTML for line breaks and to bold titles.
"""
def render_post(response, post):
    response.out.write('<b>' + post.title + '</b><br>')
    response.out.write(post.body)

"""
Since I have no landing page, I make the default URL redirect to the blog.
This is left over from my homeworks.
"""
class MainPage(Handler):

    def get(self):
        self.redirect('/blog')

"""
Generate db keys...
"""
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    return db.Key.from_path('users', group)

"""
My user class!
"""
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    """
    This to get by the actual id.
    """
    @classmethod
    def by_id(self, uid):
        return User.get_by_id(uid, parent=users_key())

    """
    This to get by name. Handy for checking for existing user names...
    """
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    """
    This to actually register the user.
    """
    @classmethod
    def register(self, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    """
    This logs the user in.
    """
    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

"""
This defines the post database object.
"""
class Post(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.body.replace('\n', '<br>')
        return jinja_render_str('post.html', p=self)

"""
This renders the front page by querying the database for the first ten entries.
"""
class BlogFront(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)

"""
This shows individual posts via a permalink based on the post id.
"""
class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

"""
This is for users to make their posts.
"""
class NewPost(Handler):
    """
    Checking if the user is logged in. If not, they are referred to
    the login page.
    """
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect('/blog/login')

    def post(self):
        title = self.request.get('title')
        body = self.request.get('body')

        """
        Making sure the user entered all required content for the post.
        """
        if title and body:
            p = Post(parent=blog_key(), title=title, body=body)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = 'Please enter a title and body.'
            self.render("newpost.html", title=title, body=body,
                        error=error)

"""
This is for users to sign in.
"""
class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        error_exists = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_u'] = "Invalid username."
            error_exists = True

        if not valid_password(self.password):
            params['error_pw'] = "Invalid password."
            error_exists = True
        elif self.password != self.verify:
            params['error_pwv'] = "Passwords don't match."
            error_exists = True

        if not valid_email(self.email):
            params['error_mail'] = "Invalid email."
            error_exists = True

        if error_exists:
            self.render('signup.html', **params)
        else:
            self.done()

    """
    Here's where we use the user.by_name function to check for existing users.
    """
    def done(self):
        u = User.by_name(self.username)
        if u:
            message = 'Username already exists.'
            self.render('signup.html', error_u=message)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/newpost')


class Login(Handler):

    def get(self):
        self.render('login.html', error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/newpost')
        else:
            message = 'Invalid login'
            self.render('login.html', error=message)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/blog/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Signup),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout)
                               ],
                              debug=True)

#!/usr/bin/env python
# TO DO:
# 1. Add ability to browse posts, browsePosts
# 2. Add ability to search posts by title and keywords
#       - create Keywords database
# 3. Add column with list of keyword tags - query all unique tags

import os
import jinja2
import webapp2
import hashlib
# contains secret string
import sources

import hmac
import random
import string
import re
from google.appengine.ext import db
from google.appengine.api import memcache
import datetime
import time
import bleach

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# secret string
secret = sources.secret()

# Custom jinja2 filter for returning first line of content
def firstline(content):
    return content.split('\n')[0]

# Custom jinja2 filter for returning standard month day year format
def standard_date(date):
    return date.strftime('%b %d, %Y')

def markdown(content):
    bleached_content = bleach.clean(content, tags = ['strong','b','i','em','h1','h2','pre','code', 'br', 'u'])
    c = bleached_content.split('\n')
    # first line (description) will be a bigger font size
    c[0] = '<h3>%s</h3>' % c[0]
    content = '\n'.join(c)
    content = content.replace('\n', '<br>')
    return content

jinja_env.filters['firstline'] = firstline
jinja_env.filters['standard_date'] = standard_date
jinja_env.filters['markdown'] = markdown

def imageCheck(url):
    if url[:19] == 'http://i.imgur.com/':
        return url

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # everything cookie related
    # -------------------------
    def make_secure_val(self, val):
        return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

    def check_secure_val(self, secure_val):
        # secure_val is checked by splitting to two
        val = secure_val.split('|')[0]
        key = secure_val.split('|')[1]
        # create a hashed value of val
        hashed = self.make_secure_val(val).split('|')[1]
        # both key and hashed has to always remain equal to confirm that there is no tampering
        if key == hashed:
            return val

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def set_remember_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        # expiry time is set one year from login
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        self.response.set_cookie(name, cookie_val, expires=expires, path='/')

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)

    def current_user(self):
        uid_cookie = self.read_secure_cookie('user_id')
        if uid_cookie:
            uid = uid_cookie.split('|')[0]
            key = db.Key.from_path('User', int(uid))
            return db.get(key)

    def logout(self, name):
        self.response.headers.add_header('Set-Cookie', '%s=; Path=/' % name)

    # makes encrypted sha256 passwords
    # --------------------------------
    def make_hash(self, name, password, salt):
        return hashlib.sha256(name + password + salt).hexdigest()

    def make_salt(self):
        # salt set to 5 characters
        return "".join(random.choice(string.letters) for x in xrange(5))

class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty()
    password = db.StringProperty(required = True)
    security_q = db.StringProperty(required = True)
    security_a = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)

class Post(db.Model):
    user_id = db.IntegerProperty(required = True)
    username = db.StringProperty(required = True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    keywords = db.StringProperty()
    likes = db.IntegerProperty(required = True)
    date_added = db.DateTimeProperty(auto_now_add = True)
    date_modified = db.DateTimeProperty(auto_now = True)
    pic = db.StringProperty()

class Comment(db.Model):
    username = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    post_id = db.IntegerProperty(required = True)
    date_added = db.DateTimeProperty(auto_now_add = True)

class Like(db.Model):
    username = db.StringProperty(required = True)
    post_id = db.IntegerProperty(required = True)

# key generator functions
def user_key(user_id):
    return db.Key.from_path('User', user_id)

def post_key(post_id, user_key):
    return db.Key.from_path('Post', post_id, parent = user_key)

def comment_key(comment_id, post_id, user_key):
    return db.Key.from_path('Comment', comment_id, parent = post_key(post_id, user_key))

# form validation functions
# -------------------------
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

def check_duplicate_user(username):
    user = User.all().filter('username =', username).get()
    if user:
        return True
    else:
        return False

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignUp(Handler):
    def get(self):
        message = self.request.get('message')
        username = self.request.get('username')
        email = self.request.get('email')
        user_logged = ''
        u = self.current_user()
        if u:
            user_logged = u.username
        self.render('signup.html', message = message, username = username, email = email, user_logged = user_logged)

    def post(self):
        username = self.request.get('username') or None
        email = self.request.get('email') or None
        password = self.request.get('password')
        verify = self.request.get('verify')
        security_q = self.request.get('security_q')
        security_a = self.request.get('security_a')
        msg = []
        err = False

        if not valid_username(username):
            msg.append('Invalid Username')
            err = True

        if check_duplicate_user(username):
            msg.append('Duplicate Username, Choose another one')
            err = True

        if not valid_password(password):
            msg.append('Invalid Password')
            err = True

        if not valid_email(email):
            msg.append('Invalid Email')
            err = True

        if not security_a:
            msg.append('Security Question and Answer required')
            err = True

        if password != verify:
            msg.append('Passwords do not match')
            err = True

        if len(password) < 8:
            msg.append('Password must be 8 or more characters')
            err = True

        if err:
            # create whole message from all error messages
            message = ", ".join(msg)
            self.render('/signup.html', message = message, username = username, email = email)
        else:
            # passed all requirements
            # create hashed password for each user
            salt = self.make_salt()
            hashed_pwd = self.make_hash(username, password, salt)
            security_a_hashed = self.make_hash(security_q, security_a, salt)

            # save to database
            u = User(username = username, email = email, password = hashed_pwd, security_q = security_q, security_a = security_a_hashed, salt = salt)
            u.put()
            self.redirect('/login?username=%s&status=signedup' % username)

class Login(Handler):
    def get(self):
        username = self.request.get('username') or ''
        status = self.request.get('status') or None

        self.logout('user_id')
        self.render('login.html', username = username, status = status)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        remember = self.request.get('remember')
        err = ''

        if (username and password):
            user = User.all().filter('username =', username).get()
            if user:
                uid = user.key().id()
                hashed_pwd = user.password
                salt = user.salt

                # make a hash of what the user entered
                hashed = self.make_hash(username, password, salt)

                # check if passwords match
                if hashed == hashed_pwd:
                    # successful login
                    if remember:
                        self.set_remember_cookie('user_id', str(uid))
                    else:
                        self.set_secure_cookie('user_id', str(uid))
                    self.redirect('/')
                else:
                    # passwords dont match
                    err = 'wrong_pwd'
            else:
                # username does not exist
                err = 'wrong_user'
        else:
            err = 'blank'

        if err:
            self.render('login.html', status = err)

class Forgot(Handler):
    def get(self):
        self.render('forgot.html')

    def post(self):
        username = self.request.get('username')
        security_q = self.request.get('security_q')
        security_a = self.request.get('security_a')
        err_msg = []
        message = ''
        err = False
        salt = ''

        if not username:
            err_msg.append('Please enter Username')
            err = True

        if not security_a:
            err_msg.append('Please enter Security Answer')
            err = True

        if not valid_username(username):
            err_msg.append('Invalid Username')
            err = True

        if not err:

            user = User.all().filter('username =', username).get()
            if user:
                uid = user.key().id()
                q_db = user.security_q
                a_db = user.security_a
                salt = user.salt
            else:
                err_msg.append("Did not find Username")
                err = True

            if salt:
                if (q_db == security_q) and (a_db == self.make_hash(security_q, security_a, salt)):
                    err = False
                else:
                    err_msg.append("Security fields do not match")
                    err = True

        if err:
            message = ", ".join(err_msg)
            self.render('forgot.html', message = message)
        else:
            # success : set cookie to user
            self.set_secure_cookie('user_id', str(uid))
            self.redirect('/change_pwd')

class ChangePwd(Handler):
    def get(self):
        #check cookie
        u = self.current_user()
        if u:
            self.render('changepwd.html', username = u.username)
        else:
            self.render('404error.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        err = False

        if not valid_password(password):
            err_msg = 'Invalid Password'
            err = True

        if password != verify and err == False:
            err_msg = 'Password and Verify Password do not match'
            err = True

        if len(password) < 8:
            err_msg = 'Password must be 8 characters'
            err = True

        if err:
            self.render('changepwd.html', message = err_msg)
        else:
            # update db
            u = self.current_user()
            if u:
                u.password = self.make_hash(username, password, u.salt)
                u.put()
            self.redirect('/blogs')

# browse all users' posts based on username
class ViewUser(Handler):
    def get(self):
        user_id = int(self.request.get('u'))
        username = db.get(user_key(user_id)).username
        posts = Post.all().filter('username =', username).order('-date_modified')
        u = self.current_user()
        user_logged = ''
        if u:
            user_logged = u.username

        self.render('viewuser.html', posts = posts, user_logged = user_logged, username = username, user_id = user_id)

class NewPost(Handler):
    def get(self):
        u = self.current_user()
        if u:
            self.render('newpost.html', user_logged = u.username, user_id = u.key().id())

    def post(self):
        u = self.current_user()
        if u:
            subject = self.request.get('subject')
            # clean up content
            content = self.request.get('content')
            keywords = self.request.get('keywords')
            pic = self.request.get('pic')
            if pic:
                # clean up URL
                pic = bleach.clean(pic)
                # check if imgur pic only
                pic = imageCheck(pic)
            username = u.username
            if subject and content:
                p = Post(parent = u.key(), user_id = u.key().id(), username = username, subject = subject, content = content, keywords = keywords, pic = pic, likes = 0)
                p.put()
                self.redirect('/view?p=%s&u=%s' % (p.key().id(), u.key().id()))
            else:
                message = 'Please include both subject and content'
                self.render('newpost.html', user_logged = u.username, message = message)


class EditPost(Handler):
    def get(self):
        post_id = int(self.request.get('pid'))
        u = self.current_user()
        if u:
            postkey = post_key(post_id, u.key())
            post = db.get(postkey)
            self.render('editpost.html', user_logged = u.username, post_id = post_id, post = post)

    def post(self):
        u = self.current_user()
        if u:
            subject = self.request.get('subject')
            content = self.request.get('content')
            keywords = self.request.get('keywords') or ''
            post_id = self.request.get('post_id')
            pic = self.request.get('pic')
            if pic:
                pic = bleach.clean(pic)
                # check if imgur pic only
                pic = imageCheck(pic)
            username = u.username
            post_key = db.Key.from_path('Post', int(post_id), parent = u.key())
            p = db.get(post_key)
            if subject and content:
                if p.username == u.username:
                    p.subject = subject
                    p.content = content
                    p.keywords = keywords
                    p.pic = pic
                    p.put()
                    self.redirect('/view?p=%s&u=%s' % (p.key().id(), u.key().id()))
            else:
                message = 'Error: please include both subject and content'
                self.render('editpost.html', user_logged = u.username, message = message)

class DeletePost(Handler):
    def post(self):
        u = self.current_user()
        if u:
            post_id = int(self.request.get('post_id'))
            post = db.get(post_key(post_id, u.key()))
            post.delete()
            self.redirect('/viewuserposts?u=%s' % u.key().id())

class ViewPost(Handler):
    def get(self):
        post_id = int(self.request.get('p'))
        user_id = int(self.request.get('u'))
        comment_id = self.request.get('c')
        message = self.request.get('m')

        user_logged = ''
        comment = ''
        username = ''
        postkey = post_key(post_id, user_key(user_id))
        post = db.get(postkey)

        u = self.current_user()
        if u:
            user_logged = u.username

        if post:
            comments = Comment.all().ancestor(postkey).order('-date_added')
            # add other filters
            if comment_id:
                commentkey = comment_key(int(comment_id), post_id, user_key(user_id))
                comment = db.get(commentkey)
            self.render('viewpost.html', post = post, comments = comments, user_id = user_id, user_logged = user_logged, comment = comment, message = message)
        else:
            self.render('404error.html')

class LikePost(Handler):
    def post(self):
        post_id = int(self.request.get('post_id'))
        user_id = int(self.request.get('user_id'))
        post_username = self.request.get('username')
        message = ''
        u = self.current_user()
        if u:
            # check if user is not liking own post
            if u.username != post_username:
                # check if post was already liked
                likes = Like.all().filter('post_id =', post_id).filter('username =', u.username).get()
                if not likes:
                    # save like
                    postkey = post_key(post_id, user_key(user_id))
                    p = db.get(postkey)
                    p.likes += 1
                    p.put()
                    l = Like(parent = postkey, username = u.username, post_id = post_id)
                    l.put()
                    self.redirect('/view?p=%s&u=%s&#likes' % (post_id, user_id))
                else:
                    message = 'You can only like a post once'
            else:
                message = 'You cannot like your own post'
            self.redirect('/view?p=%s&u=%s&m=%s&#likes' % (post_id, user_id, message))


class NewComment(Handler):
    def post(self):
        new_comment = self.request.get('new_comment')
        post_id = int(self.request.get('post_id'))
        user_id = int(self.request.get('user_id'))
        post_username = self.request.get('username')
        u = self.current_user()
        if u:
            comment = Comment(parent = post_key(post_id, user_key(user_id)), username = u.username, content = new_comment, post_id = post_id)
            comment.put()
        self.redirect('/view?p=%s&u=%s&#comments' % (post_id, user_id))

class EditComment(Handler):
    def post(self):
        comment_id = int(self.request.get('comment_id'))
        post_id = int(self.request.get('post_id'))
        user_id = int(self.request.get('user_id'))
        edited_content = self.request.get('edited_content')
        u = self.current_user()
        if u:
            commentkey = comment_key(comment_id, post_id, user_key(user_id))
            c = db.get(commentkey)
            c.content = edited_content
            c.put()
        self.redirect('/view?p=%s&u=%s&#comments' % (post_id, user_id))

class DeleteComment(Handler):
    def post(self):
        comment_id = int(self.request.get('comment_id'))
        post_id = int(self.request.get('post_id'))
        # user_id can be current viewed post's user or currently logged in user 
        user_id = int(self.request.get('user_id'))
        u = self.current_user()
        if u:
            commentkey = comment_key(comment_id, post_id, user_key(user_id))
            c = db.get(commentkey)
            c.delete()
        self.redirect('/view?p=%s&u=%s&#comments' % (post_id, user_id))

# main page
class MainHandler(Handler):
    def get(self):
        u = self.current_user()
        user_logged = None
        user_id = None
        posts = Post.all().order('-date_added')

        if u:
            user_logged = u.username
            user_id = u.key().id()

        results = posts.fetch(limit=10)
        # Get updated cursor and store it for the first time for pagination
        post_cursor = posts.cursor()
        memcache.set('post_cursor', post_cursor)

        self.render('front.html', user_logged = user_logged, user_id = user_id, posts = results, page_number = 1)

class NextResults(Handler):
    def get(self, page):
        u = self.current_user()
        user_logged = None
        user_id = None
        posts = Post.all().order('-date_added')

        post_cursor = memcache.get('post_cursor')
        if post_cursor:
            posts.with_cursor(start_cursor = post_cursor)
        if u:
            user_logged = u.username
            user_id = u.key().id()

        results = posts.fetch(limit=10)
        # Get updated cursor and store it for next time
        post_cursor = posts.cursor()
        memcache.set('post_cursor', post_cursor)

        self.render('front.html', user_logged = user_logged, user_id = user_id, posts = results, page_number = int(page)+1)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/page/([0-9]+)', NextResults),
    ('/newpost', NewPost),
    ('/editpost', EditPost),
    ('/deletepost', DeletePost),
    ('/view', ViewPost),
    ('/viewuserposts', ViewUser),
    ('/like', LikePost),
    ('/comment', NewComment),
    ('/editcomment', EditComment),
    ('/deletecomment', DeleteComment),
    ('/signup', SignUp),
    ('/login', Login),
    ('/forgot', Forgot),
    ('/change_pwd', ChangePwd)
], debug=True)

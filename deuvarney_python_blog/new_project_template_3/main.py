import os
import re 
import random
import hashlib
import hmac
import time
import string
import json
import logging

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache

jinja_environment = jinja2.Environment(autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        t = jinja_environment.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)
    
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class MainHandler(webapp2.RequestHandler):
    def get(self):
        template_values = {
            'name': 'SomeGuy',
            'verb': 'extremely enjoy'
        }

        template = jinja_environment.get_template('index.html')
        self.response.out.write(template.render(template_values))
        
    def post(self):
        template_values = {
            'name': 'SomeGuy',
            'verb': 'extremely enjoy'
        }
        
        template = jinja_environment.get_template('page_inputs/index.html')
        self.response.out.write(template.render(template_values))

class TestHandler(webapp2.RequestHandler):
    def get(self):
        name = self.request.get("username")
        template_values = {"name":name}
        template = jinja_environment.get_template('page_inputs/testform.html')
        self.response.out.write(template.render(template_values))
        
    def post(self):
        name = self.request.get("username")
        template_values = {"name":name}
        template = jinja_environment.get_template('page_inputs/testform.html')
        self.response.out.write(template.render(template_values))

class BlogHandler(Handler):
    def render_front(self): 
        all_posts = get_front_data()   
        front_refresh_time = "Queried %s seconds ago" % str(int(_front_refresh_time()));
        #all_posts = db.GqlQuery("Select * from Posts order by created_time desc")
        #all_posts = db.GqlQuery("Select * from Posts where insert_id > 99 order by insert_id desc")
        #debugging#for post in all_posts:
            #print post.subject, post.post, post.insert_id
        
        if self.format == 'html':
            #original#self.render('front.html', posts = posts)
            self.render("blogpost/blogpost.html", all_posts = all_posts, front_refresh_time = front_refresh_time)   
        else:
            return self.render_json([p.as_dict() for p in all_posts])
    
    def get(self):
        #template_values={"name":"name1"}
        #template = jinja_environment.get_template("blogpost/blogpost.html")
        #self.response.out.write(template.render(template_values))
        #logging.error("Early Access")
        self.render_front()
        
    def post(self):
        self.render_front()

class Posts(db.Model): 
    subject = db.StringProperty(required = True)
    post = db.TextProperty(required = True)
    created_time = db.DateTimeProperty(auto_now_add = True)
    insert_id =  db.IntegerProperty()    
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str("post.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.post,
             'created': self.created_time.strftime(time_fmt)
             }
             #'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class NewPostHandler(Handler):
    def render_front(self, subject="", post="", error=""):
        all_posts = db.GqlQuery("Select * from Posts")
        #self.nextAvailableId()
        self.render("blogpost/new_post/new_post.html",
                    subject= subject, post=post, error=error)

    def get(self):
        #template_values={"subject":"name1"}
        #template = jinja_environment.get_template("blogpost/new_post/new_post.html")
        #self.response.out.write(template.render(template_values))
        #self.render("blogpost/new_post/new_post.html")
        self.render_front()
        
    def nextAvailableId(self):
        all_posts = db.GqlQuery("Select * from Posts where insert_id > 1 order by insert_id desc limit 1 ") 
        x = 99
        for post in all_posts:
            x= post.insert_id
            return x + 1
        return 100
       
     
    def post(self):
        subject = self.request.get("subject")
        post = self.request.get("content")
        if subject and post:
            insert_id = self.nextAvailableId()
            p = Posts(subject=subject, post=post, insert_id=insert_id)
            p.put()

            logging.warn("DB WRite")
            #get_front_data()
            
            ####Attempting to add to the memcache
            data = memcache.get("all_posts")

            print data
            
            #p=list(p)
            print "This is p",p
            data.insert(0, p)
            print data
            #if data == data2:
            #   print"CACHE HASN'T BEEN UPDATED"
                
            #print "DATA 2", data2    
            memcache.set("all_posts", data)
            
            self.redirect("/blogpost/" +str(insert_id))
        else:
            error = "Subject and Post are required"
            self.render_front(subject=subject, post=post, error = error)

class SinglePostHandler(Handler):
    def render_front(self, number):
        #page_query = db.GqlQuery("Select * from Posts where insert_id = " + str(number))
        page_query = get_single_data(number)
        print "CHECK1"
        print page_query
        subject = None
        the_post = None
        #if not page_query:
        #    self.error(404)
        #    return
        if self.format == 'html':
            single_refresh_time = "Queried %s seconds ago" % str(int(_single_refresh_time(number)))
            for post in page_query:
                subject = post.subject
                the_post = post.post
            self.render("blogpost/new_post/single_post.html", subject=subject,
                         the_post=the_post, single_refresh_time = single_refresh_time)
        else:
            return self.render_json(page_query[0].as_dict())
            #return self.render_json([p.as_dict() for p in page_query])
        
        
    def get(self, number):
        self.render_front(number)
        #self.render_front()
                
    def post(self):
        pass

class RegistrationHandler(Handler):
    def render_front(self, user= "", email="", user_error="",
                      password_error="", verify_error="", email_error = ""):
        self.render("registration/registration.html", 
                    user= user, email = email,
                    user_error=user_error,
                    password_error = password_error,
                    verify_error = verify_error,
                    email_error = email_error                    
                    )
        #self.render("blogpost/blogpost.html", all_posts = all_posts)
    def get(self):
        self.render_front()
        
    def post(self):
        user = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        user_error= ""
        password_error = ""
        verify_error = ""
        email_error = ""
        
        if not user:
            user_error = "A username is required"  
    
        if not password:
            password_error = "A valid password is required"
            
        if password and password != verify:
            verify_error= "The passwords do not match" 
            
        if email and not valid_email(email):
            email_error = "This is not a valid email"           
        
        if user and password and password == verify and (valid_email(email) or not email):
            all_users = db.GqlQuery("Select * from Users")
            for users in all_users:
                if users.user_name.split("|")[0] == user:
                    user_error = "Unfortunately This User Name is already Taken"
                    self.render_front(user=user, email=email, user_error = user_error)
                    return
            
            if email:
                u = Users(user_name = make_hash(user), password = make_pw_hash(user, password), email_address = email)
                u.put()
            else:
                u = Users(user_name = make_hash(user), password = make_pw_hash(user, password))
                u.put()
            self.response.headers.add_header('Set-Cookie', "username=%s; Path=/" % str(make_hash(user)))
            #self.response.out.write("Goodjob")
            self.redirect("/blogpost/welcome")
            return
                    
        self.render_front(user=user, email=email,
                          user_error = user_error,
                          password_error = password_error,
                          verify_error=verify_error,
                          email_error = email_error
                          )

class WelcomeHandler(Handler):
    def get(self):
       user_name = self.request.cookies.get("username", None)
       #dubugging#print "UserName", user_name
       if user_name:
           if validate_hash(user_name):
               self.response.out.write("Welcome, %s" % user_name.split('|')[0])
               return
       #self.write("Invalid user, redirecting to sign up page")
       #time.sleep(2)
       self.redirect('/blogpost/signup') 
  
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

SECRET= "AbC123"
def hmac_str(value):
    '''helper function for making user/cookie hash '''
    x= hmac.new(SECRET, value).hexdigest()
    return x

def make_hash(value):
    '''Used for creating user/cookie hash'''
    return "%s|%s" % (value, hmac_str(value))

def make_salt():
    '''Helper function for making password hash'''
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    '''Main function for making password hash'''
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    salty = h.split('|')[1]
    x = make_pw_hash(name, pw, salty)
    if x.split('|')[0] == h.split('|')[0]:
        return True
    return False

def validate_hash(value):
    val = value.split('|')[0]
    if make_hash(val) == value:
        return val
    return None
        
class Users(db.Model):
    user_name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email_address = db.EmailProperty()
    created_time = db.DateTimeProperty(auto_now_add = True)

class LoginHandler(Handler):
    def render_front(self, user = "", user_error=""):
        self.render("login/login.html", user = user, user_error = user_error)
    def get(self):
        self.render_front()
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        username_hash = make_hash(username)
        
        all_users = db.GqlQuery("Select * from Users where user_name='%s' limit 1" % str(username_hash)) 
        
        for user in all_users:
            if valid_pw(username, password, user.password):
                self.response.headers.add_header('Set-Cookie', "username=%s; Path=/" % str(username_hash))
                self.redirect("/blogpost/welcome")
                return

        user_error = "Incorrect User or Password. \n Please Try again"
        self.render_front(user = username, user_error = user_error)
                
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', "username=%s; Path=/" % str(""))
        #self.set_cookie('username', "")
        #self.response.out.write("Goodjob")
        self.redirect("/blogpost/signup")

class JsonHandler(Handler):
    def get(self,number):
        #self.write(self.redirect('/login'))
        pass
    def post(self):
        pass

def get_front_data():
    """Function takes in a key as a parameter. If key is in memcache, function will return data.
     Otherwise function will run a database query, store the key and values in memcache and returns data"""
    key="all_posts"
    data = memcache.get(key)
    if data is not None:
        logging.warn("CACHE READ!!!")
        print "CACHE DATA", data
        return data
    
    else:
        logging.warn("DB READ!!!")
        memcache.set("front_time", time.time()) 
        data = db.GqlQuery("Select * from Posts order by created_time desc")
        data= list(data)
        memcache.set(key, data)
        return data

def get_single_data(key):
    """Function takes in a key as a parameter. If key is in memcache, function will return data.
     Otherwise function will run a database query, store the key and values in memcache and returns data"""
    data = memcache.get(key)
    if data:
        logging.warn("CACHE READ!!!")
        print "CACHE DATA", data
        return data
    
    else:
        logging.warn("DB READ!!!")
        data = db.GqlQuery("Select * from Posts where insert_id = " + str(key))
        data= list(data)
        memcache.set( str(key) +"_time", time.time()) 
        memcache.set(key, data)
        return data

def _front_refresh_time():
    """
    This function is called whenever a db read to the front page is made.  If key is in the memcache, the cache 
    returns a value of the last time the db for the front page was read. If the key is not in the cache, the db
    
    """
    front_time= memcache.get("front_time")
    return  time.time() - front_time

def _single_refresh_time(key):
    front_time= memcache.get(str(key) + "_time")
    return  time.time() - front_time
  
    
app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/testform',TestHandler),
                               ('/blogpost/?(?:\.json)?', BlogHandler), 
                               ('/blogpost/newpost', NewPostHandler),
                               ('/blogpost/([0-9]+)/?(?:\.json)?' , SinglePostHandler),
                               ('/blogpost/signup', RegistrationHandler), 
                               ('/blogpost/welcome', WelcomeHandler),
                               ('/blogpost/login', LoginHandler), 
                               ('/blogpost/logout', LogoutHandler), 
                               ("(.*)/.json", JsonHandler)
                               ], 
                              debug=True)


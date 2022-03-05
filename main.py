from flask import Flask, render_template, request, session, redirect, url_for
#from flask_session import Session
import sqlite3
import bcrypt
app = Flask('app')

app.config["SECRET_KEY"] = 'egg'

#Andrew Womack // Build-a-Blog

conn = sqlite3.connect('database.db')
c = conn.cursor()

#database creation code
#c.execute("""CREATE TABLE posts (
#  pid INTEGER PRIMARY KEY AUTOINCREMENT,
#  title text NOT NULL,
#  content text NOT NULL,
#  ownerid text
#)""")
#
##
#c.execute("""CREATE TABLE users (
#  uid INTEGER PRIMARY KEY AUTOINCREMENT,
#  username text UNIQUE,
#  password text NOT NULL
#)""")

#EDITOR NOTE YOU MUST RUN THESE WITHIN SQL FUNCTIONS OR THEY CREATE TEMPORARY DB FILES
#-------------------------------------------------------------------------------------
#sql_two("INSERT INTO users (username, password) VALUES ('Jim','cheese')")
#c.execute("INSERT INTO posts (title, content) VALUES ('Test Title','This is test content')")
#print(c.fetchall())
username_global = None

def sql(sql_command, values):
  conn = sqlite3.connect('database.db', check_same_thread=False)
  c = conn.cursor()
  query = c.execute(sql_command, values).fetchall()
  conn.commit()
  conn.close()
  return query

def sql_two(sql_command):
  conn = sqlite3.connect('database.db', check_same_thread=False)
  c = conn.cursor()
  query = c.execute(sql_command).fetchall()
  conn.commit()
  conn.close()
  return query


@app.route('/')
def initialize_page():
  query = sql_two('SELECT * FROM posts')
  id = request.args.get('pid')
  if id != None:
    title = sql('SELECT title FROM posts WHERE pid=?',(id,))
    content = sql('SELECT content FROM posts WHERE pid=?',(id,))
    ownerid = sql('SELECT ownerid FROM posts WHERE pid=?',(id))
    #guinness world record book of dumbest solutions to a problem ever
    #format_string_title = str(title)
    #format_string_title = format_string_title.replace("[('", "")
    #format_string_title = format_string_title.replace("',)]", "")
    #format_string_content = str(content)
    #format_string_content = format_string_content.replace("[('", "")
    #format_string_content = format_string_content.replace("',)]", "")
    if ownerid == None:
      ownerid = username_global
    return render_template('individual.html', title = title[0][0], content = content[0][0], ownerid = ownerid[0][0])  #Yes I figured out how to do this eventually lol
  return render_template('home.html', query = query)


@app.route('/postpage')
def post_link():
  if username_global == None:
    return render_template("login.html")
  else:
    return render_template('postpage.html')

@app.route('/postpage', methods=["POST"])
def post_add():
  error = "Blog post must have title and content"
  title = str(request.form.get("Title"))
  content = str(request.form.get("Content"))
  name = username_global
  if title != "" and content != "":
    sql('INSERT INTO posts (title, content, ownerid ) VALUES (?,?,?)', (title, content, name))
    return render_template('postadded.html', title = title, content = content, ownerid = name )
  else: return render_template('postpage.html', message = error)


#NEW STUFF--------------------------------------------------------------

#join_tables = sql_two('SELECT username FROM users')
#sql('INSERT INTO posts (ownerid) VALUES (?)',(join_tables))


#def login_validation():
#  return render_template("login.html")

@app.route('/login')
def login_link():
  if username_global == None:
    return render_template("login.html")
  else: return render_template("postpage.html")

@app.route('/login', methods=['POST'])
def login_validation():
  #query = sql_two('SELECT username FROM users')
  username_form = str(request.form.get("username"))
  password_form = str(request.form.get("password"))
  username_db = sql('SELECT username FROM users WHERE username=?',(username_form,))
  password_db = sql('SELECT password FROM users WHERE username=?',(username_form,))
  username_validated = False
  password_validated = False
  message = "Login Failed, try re-entering username and password"

  for items in username_db:
    if username_db[0][0] == username_form:
      username_validated = True
  
  for items in password_db:
    if bcrypt.checkpw(password_form.encode('utf-8'), password_db[0][0]):
      password_validated = True
    #else: message = "Password did not match our records, try retyping"
    #password_validated = False


  #for items in password_db:
  #  if password_db[0][0] == password_form:
  #    password_validated = True
      
  if username_validated and password_validated:
    global username_global
    username_global = username_form
    #if username_global == username_form:
      #sql('INSERT INTO posts (ownerid) VALUES (?)', (username_global))
    return render_template("postpage.html", message="Login Successful, enjoy posting")

  if not username_validated:
    return render_template("login.html", message = "Username does not match our records")
  if not password_validated and username_validated:
    return render_template("login.html", message = "Password does not match our records")
  
  return render_template("login.html", message = message)

@app.route('/signup')
def signup_link():
  return render_template("signup.html")

@app.route('/signup', methods=["POST"])
def signup_add():
  username = str(request.form.get("username"))
  password = str(request.form.get("password"))
  verify_password = str(request.form.get("verify_password"))
  message="default"
  username_validated = True


  if len(username) == 0 or len(password) == 0:
    username_validated = False
    message = "All fields must be filled in"

  #username_db = sql('SELECT username FROM users WHERE username=?',(username,))
  #if username_db != None:
  #  username_validated = False
  #  message = username_db[0]


  if password != verify_password:
    username_validated = False
    message = "Password and verify must be EQUAL"

  if len(username) < 3 or len(password) < 3:
    username_validated = False
    message = "Username and password must be longer than 3 characters"

  if username_validated:
    global username_global
    username_global = username
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
      sql('INSERT INTO users (username, password) VALUES (?,?)', (username, hashed))
      return render_template('postpage.html', message="Sign-up was successful, enjoy  posting")
    except sqlite3.IntegrityError:
      return render_template("signup.html",message = "Username exists already, allegedly")
  else: return render_template("signup.html",message = message)
  

def print(value):
  print(value)

@app.route('/singleuser', methods=["POST", "GET"])
def single_user():
  #query = sql('SELECT * FROM posts')
  user = request.args.get('users')

  #title = sql('SELECT title FROM posts WHERE ownerid=?',(user,))
  #content = sql('SELECT content FROM posts WHERE ownerid=?',(user,))
  #ownerid = sql('SELECT ownerid FROM posts WHERE ownerid=?',(user,))
  query = sql('SELECT * FROM posts WHERE ownerid=?',(user,))
  return render_template("singleuser.html", query = query)


@app.route('/user')
def user_session():
  if session.get("USERNAME", None) is not None:
    username = session.get("USERNAME")
    return render_template("postpage.html", message = username)
  return render_template("login.html")

@app.route('/logout')
def logout_process():
  session.pop('USERNAME', None)
  global username_global
  username_global = None
  return initialize_page()

#NEWSTUFF^^^-----------------

app.run(host='0.0.0.0', port=8080)
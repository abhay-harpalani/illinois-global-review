import time
from jinja2 import TemplateError
from flask import Flask, redirect, url_for, render_template, flash, request
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import BooleanField, StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from typing import List
import os
import os.path
import bcrypt
import random

app = Flask(__name__)
# used for sessions
with open(".env", 'r') as f:
	app.secret_key = f.read()
login_manager = LoginManager()
login_manager.init_app(app)


class NewUserForm(FlaskForm):
	email = StringField('Email Address', validators=[DataRequired(), Length(min=7)])
	name = StringField('Full Name (First Last)', validators=[DataRequired(), Length(min=3)])
	username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
	password = PasswordField('Password', validators=[DataRequired(), Length(min=10, max=50)])
	confirm_password = PasswordField('Confirm Password', validators=[
		EqualTo('password', message='Passwords must match.'), Length(min=10)
	])


class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
	password = PasswordField('Password', validators=[DataRequired(), Length(min=10, max=50)])
	remember_me = BooleanField('Remember Me?')


class ArticleForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()])
	author = StringField('Author', validators=[DataRequired()])
	body = TextAreaField('Body', validators=[DataRequired()])
	cover_image = FileField(
		'Cover Image', validators=[FileRequired(), FileAllowed(['jpg', 'png', 'jpeg', 'webp'], 'Please upload a jpg or png file')]
	)
	cover_image_alt_text = StringField('Cover Image Alt Text', validators=[DataRequired()])
	cover_image_source = StringField('Cover Image Source', validators=[DataRequired()])
	na_tag = BooleanField('North America')
	sa_tag = BooleanField('South America')
	eu_tag = BooleanField('Europe')
	af_tag = BooleanField('Africa')
	as_tag = BooleanField('Asia')
	oc_tag = BooleanField('Oceania')


class Article:
	title: str
	author: str
	# id of the article, visible in URL
	article_id: str
	# creation date of the article represented as unix epoch time
	creation_date_epoch: str
	# date that the article was last edited
	edit_date_epoch: str
	# tags for the article (north america, south america, asia, africa, europe, oceania)
	# abbreviated to "na", "sa", "eu", "af", "as", "oc"
	tags: List[str]
	# name of cover image so that /static/img/{cover_image_name} points to image location (includes file extension)
	cover_image_name: str
	# alt text for image for screen readers
	cover_image_alt_text: str
	# source text under image
	cover_image_source: str
	# content of the article formatted with html tags
	body: str

	def __init__(self, title, author, article_id, creation_date_epoch, edit_date_epoch, tags, cover_image_name,
				 cover_image_alt_text, cover_image_source, body):
		self.title = title
		self.author = author
		self.article_id = article_id
		self.creation_date_epoch = creation_date_epoch
		self.edit_date_epoch = edit_date_epoch
		self.tags = tags
		self.cover_image_name = cover_image_name
		self.cover_image_alt_text = cover_image_alt_text
		self.cover_image_source = cover_image_source
		self.body = body


# stores information on people allowed to manage articles
class User:
	username: str
	name: str
	# hashed_password automatically salted with bcrypt
	hashed_password: List[bytes]
	email: str

	def __init__(self, username, name, hashed_password, email):
		self.username = username
		self.name = name
		self.hashed_password = hashed_password
		self.email = email

	def is_authenticated(self):
		return True

	def is_active(self):
		return True

	def is_anonymous(self):
		return False

	def get_id(self):
		return self.username


""" helper functions """

@login_manager.user_loader
def load_user(user_id):
	try:
		with open("users/" + user_id + ".txt", 'r') as f:
			user_file = f.read()
	except FileNotFoundError:
		print("could not find user with id:", user_id)
		return None
	user_lines = user_file.split("\n")
	if len(user_lines) != 4:
		print("users/" + user_id + ".txt", "does not have exactly 4 lines (username, hashed_password, name, email)")
		return None
	username = user_lines[0]
	hashed_password = user_lines[1]
	name = user_lines[2]
	email = user_lines[3]
	return User(username=username, hashed_password=hashed_password, email=email, name=name)


def load_article(article_id: str) -> (Article, Exception):
	article_path = "articles/" + article_id + ".txt"
	try:
		with open(article_path, 'r') as f:
			lines = []
			for i in range(9):
				# [:-1] removes \n from end of line
				lines.append(f.readline()[:-1])
			# body can have newlines in it so we just read the rest of the file
			lines.append(f.read())
	except FileNotFoundError:
		return None, FileNotFoundError

	title = lines[0]
	author = lines[1]
	article_id = lines[2]
	creation_date_epoch = lines[3]
	edit_date_epoch = lines[4]
	tags = lines[5].split(" ")
	cover_image_name = lines[6]
	cover_image_alt_text = lines[7]
	cover_image_source = lines[8]
	body = lines[9]
	ret = Article(title, author, article_id, creation_date_epoch, edit_date_epoch, tags, cover_image_name,
				  cover_image_alt_text, cover_image_source, body)
	return ret, None

def save_article(article: Article):
	article_path = "articles/" + article.article_id + ".txt"
	with open(article_path, 'w') as f:
		file_content = article.title + "\n" + article.author + "\n" + article.article_id + "\n"
		file_content += str(article.creation_date_epoch) + "\n" + str(article.edit_date_epoch) + "\n" + " ".join(article.tags)
		file_content += "\n" + article.cover_image_name + "\n" + article.cover_image_alt_text + "\n"
		file_content += article.cover_image_source + "\n" + article.body
		f.write(file_content)

def hash_password(password: str) -> str:
	salt = bcrypt.gensalt()
	pw = bcrypt.hashpw(password.encode('utf-8'), salt)
	return pw.decode('utf-8')


def get_all_articles():
	article_list = []
	# traverse through all articles and add them to article_list
	for filename in os.listdir("articles/"):
		full_filename = os.path.join("articles/", filename)
		# only add to article list if it is a file that ends in .txt
		if os.path.isfile(full_filename) and full_filename[-len(".txt"):] == ".txt":
			art, err = load_article(filename[:-len(".txt")])
			if err:
				print("error loading article", filename[:-len(".txt")], "with path", full_filename)
			else:
				article_list.append(art)
	# sort article_list in descending order so that most recent articles are towards front of list
	article_list.sort(key=lambda article: article.creation_date_epoch, reverse=True)
	return article_list
""" routing functions """


# files in "static" folder automatically served
@app.route("/", methods=['GET'])
def index():
	article_list = get_all_articles()

	# 2 most recent articles go in big cards at top of home page
	articles_big_card = article_list[:2]
	# the 15 articles after that (5 rows of 3 articles) go in small cards on home page
	# articles_small_card is a list of lists, where each inner element is a row of Article objects to be displayed
	articles_small_card = [article_list[i:i+3] for i in range(2, min(17, len(article_list)), 3)]
	return render_template("index.html", title="Home", articles_big_card=articles_big_card,
						   articles_small_card=articles_small_card, current_user=current_user)


@app.route("/articles/<article_id>.html", methods=['GET'])
def articles(article_id):
	# load article and redirect to edit page if it does not exist
	article, err = load_article(article_id)
	if err:
		if current_user.is_authenticated:
			return redirect(url_for("edit", article_id=article_id))
		else:
			return render_template("404.html", current_user=current_user)
	return render_template("article.html", title=article.title, article=article, current_user=current_user)


# sections for continents (north america, south america, asia, etc.)
@app.route("/section/<url_tag>", methods=['GET'])
def section(url_tag):
	# format for each section:
	# 	url path: [abbreviation in article txt files, display name]
	sections_dict = {
		"north_america": ["na", "North America"],
		"europe": ["eu", "Europe"],
		"asia": ["as", "Asia"],
		"africa": ["af", "Africa"],
		"south_america": ["sa", "South America"],
		"oceania": ["oc", "Oceania"],
	}

	# get requested section as a string
	try:
		section_tag = sections_dict[url_tag][0]
		section_name = sections_dict[url_tag][1]
	except KeyError:
		print("error: section not found")
		return redirect("/")

	section_article_list = []
	for filename in os.listdir("articles/"):
		full_filename = os.path.join("articles/", filename)
		# only add to article list if it is a file
		if os.path.isfile(full_filename):
			art, err = load_article(filename[:-len(".txt")])
			if err:
				print("error loading article", filename[:-len(".txt")], "with path ", full_filename)
			elif section_tag in art.tags:
				# only include articles with specified section tag
				section_article_list.append(art)
	# sort section_article_list in descending order so that most recent articles are towards front of list
	section_article_list.sort(key=lambda article: article.creation_date_epoch, reverse=True)

	# articles_small_card is a list of lists, where each inner element is a row of Article objects to be displayed
	# display all section articles on this page
	section_articles = [section_article_list[i:i + 3] for i in range(0, len(section_article_list), 3)]
	try:
		return render_template("section.html", title=section_name, section_articles=section_articles, current_user=current_user)
	except TemplateError:
		print("error rendering section", section_name)
		return redirect("/")


@app.route("/edit/<article_id>.html", methods=['GET', 'POST'])
@app.route("/edit/", methods=['GET', 'POST'])
def edit(article_id=None):
	if not current_user.is_authenticated:
		return render_template("403.html", current_user=current_user)
	form = ArticleForm()
	if form.validate_on_submit():
		title = form.title.data
		author = form.author.data
		creation_date_epoch = time.time()
		edit_date_epoch = 0
		body = str(form.body.data).replace("\r\n\r\n", "\n<br>\n<br>\n").replace("\n\n", "\n<br>\n<br>\n")

		# handle cover image
		cover_image = form.cover_image.data
		_, file_extension = os.path.splitext(cover_image.filename)
		unique_filename = article_id + file_extension
		cover_image_name = os.path.join("static/article_img", unique_filename)
		cover_image.save(cover_image_name) # save uploaded image
		cover_image_name = "/" + cover_image_name

		cover_image_alt_text = form.cover_image_alt_text.data
		cover_image_source = form.cover_image_source.data
		tags_data = [form.na_tag.data, form.sa_tag.data, form.eu_tag.data, form.af_tag.data, form.as_tag.data,
					 form.oc_tag.data]
		tags = []
		if tags_data[0]:
			tags.append("na")
		if tags_data[1]:
			tags.append("sa")
		if tags_data[2]:
			tags.append("eu")
		if tags_data[3]:
			tags.append("af")
		if tags_data[4]:
			tags.append("as")
		if tags_data[5]:
			tags.append("oc")
		article = Article(title=title, author=author, article_id=article_id, creation_date_epoch=creation_date_epoch,
						  edit_date_epoch=edit_date_epoch, tags=tags, cover_image_name=cover_image_name,
						  cover_image_alt_text=cover_image_alt_text, cover_image_source=cover_image_source, body=body)
		save_article(article)
		return redirect(url_for("articles", article_id=article.article_id))
	article = None
	if article_id is None or not os.path.isfile("articles/" + article_id + ".txt"):
		# article_id is None -> called /edit/ (new article)
		# not os.path.isfile("articles/" + article_id + ".txt") -> called /edit/<article_id> on nonexistent article_id
		article_id = random.randint(0, 2**31)
	else:
		# article already exists (editing existing article) -> populate form
		article, _ = load_article(article_id)
		article.body = article.body.replace("\n<br>\n<br>\n", "\n\n")

		form = ArticleForm(obj=article)
		form.na_tag.data = "na" in article.tags
		form.sa_tag.data = "sa" in article.tags
		form.eu_tag.data = "eu" in article.tags
		form.af_tag.data = "af" in article.tags
		form.as_tag.data = "as" in article.tags
		form.oc_tag.data = "oc" in article.tags
	return render_template("edit.html", form=form, article=article, article_id=article_id, current_user=current_user)


@app.route("/login/", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember_me = form.remember_me.data

		if not os.path.isfile('users/' + username + ".txt"):
			# user tried to log in to account that doesn't exist
			flash("Invalid username or password.", "danger")
			return render_template("login.html", form=form, current_user=current_user)
		else:
			with open('users/' + username + ".txt", "r") as f:
				# get hashed_password line from user file
				hashed_password = f.readlines()[1]
			user = load_user(username)

			if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
				flash("Invalid username or password.", "danger")
				return render_template("login.html", form=form, current_user=current_user)
			login_user(user, remember=remember_me)
			return redirect(url_for("dashboard"))
	return render_template("login.html", form=form, current_user=current_user)


@app.route("/logout/", methods=['GET', 'POST'])
def logout():
	logout_user()
	return redirect("/")


@app.route("/new_user/<new_user_otp>", methods=['GET', 'POST'])
def new_user(new_user_otp):
	with open('new_user_otp_list.txt', 'r') as f:
		new_user_otp_list = f.read().split("\n")

	if new_user_otp not in new_user_otp_list:
		return render_template("403.html", current_user=current_user)

	form = NewUserForm()
	if form.validate_on_submit():
		email = form.email.data
		name = form.name.data
		username = form.username.data
		password = form.password.data

		if os.path.isfile('users/' + username + ".txt"):
			# user tried to create username that already exists
			flash("That username already exists, please pick a different one.", "danger")
			form.username.data = ""
		else:
			user_filename = 'users/' + username + '.txt'
			hashed_password = hash_password(password)
			with open(user_filename, 'w') as f:
				f.write(username + "\n" + hashed_password + "\n" + name + "\n" + email)

			# automatically log in user after they create an account
			user = load_user(username)
			login_user(user)

			with open('new_user_otp_list.txt', 'r') as f:
				old_content = f.read().split("\n")
			old_content.remove(str(new_user_otp))
			new_content = "\n".join(old_content)
			with open('new_user_otp_list.txt', 'w') as f:
				f.write(new_content)

			return redirect(url_for("dashboard"))
	return render_template("new_user.html", form=form, otp=new_user_otp, current_user=current_user)


@app.route("/dashboard/", methods=['GET'])
def dashboard():
	if not current_user.is_authenticated:
		return render_template("403.html", current_user=current_user)
	return render_template("dashboard.html", article_list=get_all_articles(), current_user=current_user)

@app.route("/")
def index_handler():
	return render_template("index.html", title="Home")

if __name__ == "__main__":
	app.run(debug=True)

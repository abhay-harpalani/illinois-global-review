import time
from datetime import datetime
import os
import os.path
from flask import Flask, redirect, url_for, render_template, flash, request, send_file, make_response
from flask_login import LoginManager, login_user, logout_user, current_user
from jinja2 import TemplateError
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import BooleanField, StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from typing import List
from dataclasses import dataclass
from dotenv import load_dotenv, dotenv_values
import bcrypt
from random import choices, randint
import json

app = Flask(__name__)

# 16 MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# create .env if it doesn't exist (used for user sessions)
try:
	with open('.env', 'x') as f:
		# set key as 64 character long random string
		ascii_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
		new_secret = ''.join(choices(ascii_chars, k=64))
		f.write(f"SECRET={new_secret}")
except FileExistsError:
	pass
load_dotenv()

app.secret_key = dotenv_values('.env')['SECRET']
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


# all variables in this class correspond to a member variable of the Article class
class ArticleForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()])
	author = StringField('Author', validators=[DataRequired()])
	body = TextAreaField('Body', validators=[DataRequired()])
	cover_image = FileField('Cover Image')
	cover_image_alt_text = StringField('Cover Image Alt Text', validators=[DataRequired()])
	cover_image_source = StringField('Cover Image Source', validators=[DataRequired()])
	# not required, it may be possible for an article to not need citations
	citation = TextAreaField('Citation')
	# each tag needs its own checkbox
	# tags are stored in Article class as a list of strings
	na_tag = BooleanField('North America')
	sa_tag = BooleanField('South America')
	eu_tag = BooleanField('Europe')
	af_tag = BooleanField('Africa')
	as_tag = BooleanField('Asia')
	oc_tag = BooleanField('Oceania')


@dataclass
class Article:
	title: str
	author: str
	# id of the article, visible in URL
	article_id: str
	# creation date of the article represented as unix epoch time
	creation_date_epoch: str
	# date that the article was last edited
	edit_date_epoch: str
	# tags for the article (north america, europe, asia, africa, south america, oceania)
	# abbreviated to "na", "sa", "eu", "af", "as", "oc"
	tags: List[str]
	# name of cover image so that /static/img/{cover_image_name} points to image location (includes file extension)
	cover_image_name: str
	# alt text for image for screen readers
	cover_image_alt_text: str
	# source text under image
	cover_image_source: str
	# citation at bottom of page, has different format when viewing article page
	citation: str
	# content of the article formatted with html tags
	body: str


# stores information on people allowed to manage articles
@dataclass
class User:
	username: str
	name: str
	# hashed_password automatically salted with bcrypt
	hashed_password: str
	email: str

	def is_authenticated(self) -> bool:
		return True

	def is_active(self) -> bool:
		return True

	def is_anonymous(self) -> bool:
		return False

	def get_id(self) -> str:
		return self.username


@dataclass
class SitemapURL:
	loc: str
	lastmod: str

''' helper functions '''


@login_manager.user_loader
def load_user(user_id):
	try:
		with open(f"users/{user_id}.txt", 'r') as f:
			user_file = f.read()
	except FileNotFoundError:
		print("could not find user with id:", user_id)
		return None
	user_lines = user_file.split("\n")
	if len(user_lines) != 4:
		print(f"users/{user_id}.txt", "does not have exactly 4 lines (username, hashed_password, name, email)")
		return None
	username = user_lines[0]
	hashed_password = user_lines[1]
	name = user_lines[2]
	email = user_lines[3]
	return User(username=username, hashed_password=hashed_password, email=email, name=name)


def load_article(article_id: str) -> (Article, Exception):
	article_path = f"articles/{article_id}.json"
	ret = ''
	try:
		with open(article_path, 'r') as f:
			try:
				# return Article and no error if json is valid
				return json.load(f, object_hook=lambda d: Article(**d)), None
			except json.JSONDecodeError as err:
				return None, err
	except FileNotFoundError:
		return None, FileNotFoundError


def save_article(article: Article):
	article_path = f"articles/{article.article_id}.json"
	with open(article_path, 'w') as f:
		# file_content = article.title + "\n" + article.author + "\n" + article.article_id + "\n"
		# file_content += str(article.creation_date_epoch) + "\n" + str(article.edit_date_epoch) + "\n" + " ".join(
		# 	article.tags)
		# file_content += "\n" + article.cover_image_name + "\n" + article.cover_image_alt_text + "\n"
		# file_content += article.cover_image_source + "\n" + article.body
		f.write(json.dumps(article.__dict__, indent=4))


def get_article_creation_date_str(article: Article):
	dt = datetime.fromtimestamp(int(article.creation_date_epoch))
	ret = dt.strftime("%B %d, %Y")
	return ret


@app.context_processor
def inject_functions():
	return dict(get_article_creation_date_str=get_article_creation_date_str)


def hash_password(password: str) -> str:
	salt = bcrypt.gensalt()
	pw = bcrypt.hashpw(password.encode('utf-8'), salt)
	return pw.decode('utf-8')


def get_all_articles():
	article_list = []
	# traverse through all articles and add them to article_list
	for filename in os.listdir("articles/"):
		full_filename = os.path.join("articles/", filename)
		# only add to article list if it is a file that ends in .json
		if os.path.isfile(full_filename) and full_filename[-len(".json"):] == ".json":
			art, err = load_article(filename[:-len(".json")])
			if err:
				print("error loading article", filename[:-len(".json")], "with path", full_filename)
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
	articles_small_card = [article_list[i:i + 3] for i in range(2, min(17, len(article_list)), 3)]
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
	# 	url path: [abbreviation in article json files, display name]
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
			art, err = load_article(filename[:-len(".json")])
			if err:
				print("error loading article", filename[:-len(".json")], "with path ", full_filename)
			elif section_tag in art.tags:
				# only include articles with specified section tag
				section_article_list.append(art)
	# sort section_article_list in descending order so that most recent articles are towards front of list
	section_article_list.sort(key=lambda article: article.creation_date_epoch, reverse=True)

	# articles_small_card is a list of lists, where each inner element is a row of Article objects to be displayed
	# display all section articles on this page
	section_articles = [section_article_list[i:i + 3] for i in range(0, len(section_article_list), 3)]
	try:
		return render_template("section.html", title=section_name, section_articles=section_articles,
		                       current_user=current_user)
	except TemplateError:
		print("error rendering section", section_name)
		return redirect("/")


@app.route("/directory/", methods=['GET'])
def directory():
	article_list = get_all_articles()
	return render_template("directory.html", article_list=article_list, current_user=current_user)


@app.route("/edit/<article_id>.html", methods=['GET', 'POST'])
@app.route("/edit/", methods=['GET', 'POST'])
def edit(article_id=None):
	if not current_user.is_authenticated:
		return render_template("403.html", current_user=current_user)
	form = ArticleForm()
	if form.validate_on_submit():
		if article_id is None:
			article_id = str(randint(0, 2 ** 31))
		title = form.title.data
		author = form.author.data
		# only update creation date if we are creating a new article
		# if editing an existing article keep date the same
		if os.path.isfile(f'articles/{article_id}.json'):
			art, _ = load_article(article_id)
			creation_date_epoch = art.creation_date_epoch
		else:
			creation_date_epoch = str(int(time.time()))

		edit_date_epoch = '0'
		body = str(form.body.data)

		# handle cover image
		cover_image = form.cover_image.data
		if cover_image:
			# this is a new article or we are editing the image in an existing article
			_, file_extension = os.path.splitext(cover_image.filename)
			unique_filename = article_id + file_extension
			cover_image_name = os.path.join("static/article_img", unique_filename)
			if os.path.exists(cover_image_name):
				os.remove(cover_image_name)
			cover_image.save(cover_image_name)  # save uploaded image
			cover_image_name = "/" + cover_image_name
		else:
			# this is an existing article and the image is not being edited
			# keep cover_image_name the same
			temp, _ = load_article(article_id)
			cover_image_name = temp.cover_image_name

		cover_image_alt_text = form.cover_image_alt_text.data
		cover_image_source = form.cover_image_source.data
		citation = form.citation.data
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
		                  cover_image_alt_text=cover_image_alt_text, cover_image_source=cover_image_source,
		                  citation=citation, body=body)
		save_article(article)
		return redirect(url_for("articles", article_id=article.article_id))
	article = None
	if article_id is None or not os.path.isfile(f"articles/{str(article_id)}.json"):
		# article_id is None -> called /edit/ (new article)
		# not os.path.isfile(f"articles/{article_id}.json") -> called /edit/<article_id> on nonexistent article_id
		article_id = str(randint(0, 2 ** 31))
		form.cover_image.validators = [FileRequired(), FileAllowed(['jpg', 'png', 'jpeg', 'webp'], 'Please upload a jpg or png file')]
	else:
		# article already exists (editing existing article) -> populate form
		article, _ = load_article(article_id)

		form = ArticleForm(obj=article)
		form.cover_image.validators = [FileAllowed(['jpg', 'png', 'jpeg', 'webp'], 'Please upload a jpg or png file')]
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

		if not os.path.isfile(f'users/{username}.txt'):
			# user tried to log in to account that doesn't exist
			flash("Invalid username or password.", "danger")
			return render_template("login.html", form=form, current_user=current_user)
		else:
			with open(f'users/{username}.txt', "r") as f:
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

		if os.path.isfile(f'users/{username}.txt'):
			# user tried to create username that already exists
			flash("That username already exists, please pick a different one.", "danger")
			form.username.data = ""
		else:
			user_filename = f'users/{username}.txt'
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


@app.route('/robots.txt', methods=['GET'])
def robots():
	return send_file('static/txt/robots.txt')

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
	sitemap_urls = []
	all_articles = get_all_articles()

	# base_url will be 'https://globalreview.web.illinois.edu/' on main site
	base_url = request.url_root
	for art in all_articles:
		art_loc = base_url + art.article_id
		# formatted as YYYY-MM-DD, for example 2024-12-31
		art_last_mod = time.strftime('%Y-%m-%d')
		obj = SitemapURL(loc=art_loc, lastmod=art_last_mod)
		sitemap_urls.append(obj)

	template = render_template('sitemap.html', sitemap_urls=sitemap_urls)
	response = make_response(template)
	response.headers['Content-Type'] = 'application/xml'
	return response

@app.route('/')
def index_handler():
	return render_template("index.html", title="Home")


if __name__ == "__main__":
	app.run(host='0.0.0.0', debug=True)

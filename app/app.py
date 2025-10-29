import time
from datetime import datetime
import os
import os.path
from flask import Flask, redirect, url_for, render_template, flash, request, send_file, make_response
from flask_login import LoginManager, login_user, logout_user, current_user
from jinja2 import TemplateError
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import BooleanField, StringField, PasswordField, TextAreaField, SelectMultipleField, FieldList, FormField
from wtforms.validators import DataRequired, EqualTo, Length
from typing import List, Any, Dict
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
		f.write(f'SECRET={new_secret}')
except FileExistsError:
	pass
load_dotenv()

if not os.path.exists('app_files/tags.json'):
	print('tags.json file not present')
	exit(1)
# keys are url subpaths and values are formatted tags names (e.g. north_america: North America)
url_to_tag_dict: Dict[str, str] = dict()
# load tags from json file
with open('app_files/tags.json', 'r') as f:
	data = json.load(f)
	assert isinstance(data, dict)
	url_to_tag_dict = data
print(f'url_to_tag_dict: {url_to_tag_dict}')

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

	# convert dict to list of tuples
	article_tags = SelectMultipleField('Select any relevant tags:',
	                                   choices=[(k, v) for k, v in url_to_tag_dict.items()])


# updates the ArticleForm class, call this when url_to_tag_dict is updated
def update_articleform_tag_choices():
	ArticleForm.article_tags = SelectMultipleField('Select any relevant tags:',
	                                               choices=[(k, v) for k, v in url_to_tag_dict.items()])


class TagEditForm(FlaskForm):
	new_tag = StringField('Tag Name', validators=[DataRequired()])


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
	# abbreviated to 'na', 'sa', 'eu', 'af', 'as', 'oc'
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

	''' these 4 methods are needed for the login manager '''

	def is_authenticated(self) -> bool:
		return True

	def is_active(self) -> bool:
		return True

	def is_anonymous(self) -> bool:
		return False

	def get_id(self) -> str:
		return self.username


# used for sitemap.xml
@dataclass
class SitemapURL:
	loc: str
	lastmod: str


''' helper functions '''


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
	try:
		with open(f'users/{user_id}.txt', 'r') as f:
			user_file = f.read()
	except FileNotFoundError:
		print(f'load_user({user_id}): could not find user')
		return None
	user_lines = user_file.split('\n')
	if len(user_lines) != 4:
		print(f'load_user({user_id}): file does not have exactly 4 lines (username, hashed_password, name, email)')
		return None
	username = user_lines[0]
	hashed_password = user_lines[1]
	name = user_lines[2]
	email = user_lines[3]
	return User(username=username, hashed_password=hashed_password, email=email, name=name)


# returns Article object with the given id if found
# otherwise returns None if an error was encountered
def load_article(article_id: str) -> Any | None:
	article_path = f'articles/{article_id}.json'
	try:
		with open(article_path, 'r') as f:
			try:
				# return Article and no error if json is valid
				return json.load(f, object_hook=lambda d: Article(**d))
			except json.JSONDecodeError as err:
				print(f'load_article: json decode error for id {article_id}')
				return None
	except FileNotFoundError:
		print(f'load_article: file not found error for id {article_id}')
		return None


def save_article(article: Article) -> None:
	article_path = f'articles/{article.article_id}.json'
	with open(article_path, 'w') as f:
		f.write(json.dumps(article.__dict__, indent=4))


def get_article_creation_date_str(article: Article) -> str:
	dt = datetime.fromtimestamp(int(article.creation_date_epoch))
	ret = dt.strftime('%B %d, %Y')
	return ret


@app.context_processor
def inject_functions():
	return dict(get_article_creation_date_str=get_article_creation_date_str)


def hash_password(password: str) -> str:
	salt = bcrypt.gensalt()
	pw = bcrypt.hashpw(password.encode('utf-8'), salt)
	return pw.decode('utf-8')


def get_all_articles() -> List[Article]:
	article_list = []
	# traverse through all articles and add them to article_list
	for filename in os.listdir('articles/'):
		full_filename = os.path.join('articles/', filename)
		# only add to article list if it is a file that ends in .json
		if os.path.isfile(full_filename) and full_filename[-len('.json'):] == '.json':
			art = load_article(filename[:-len('.json')])
			if art is None:
				print(f'get_all_articles: error loading article {filename} with path {full_filename}')
				continue
			article_list.append(art)
	# sort article_list in descending order so that most recent articles are towards the top of the page
	article_list.sort(key=lambda article: article.creation_date_epoch, reverse=True)
	return article_list


''' routing functions '''


# files in 'static' folder automatically served
@app.route('/', methods=['GET'])
def index():
	article_list = get_all_articles()
	# 2 most recent articles go in big cards at top of home page
	articles_big_card = article_list[:2]
	# the 15 articles after that (5 rows of 3 articles) go in small cards on home page
	# articles_small_card is a list of lists, where each inner element is a row of Article objects to be displayed
	articles_small_card = [article_list[i:i + 3] for i in range(2, min(17, len(article_list)), 3)]
	return render_template('index.html', title='Home', articles_big_card=articles_big_card,
	                       articles_small_card=articles_small_card, url_to_tag_dict=url_to_tag_dict,
	                       current_user=current_user)


@app.route('/articles/<article_id>.html', methods=['GET'])
def articles(article_id: str):
	# load article and redirect to edit page if it does not exist
	article = load_article(article_id)
	if article is None:
		if current_user.is_authenticated:
			return redirect(url_for('edit', article_id=article_id))
		else:
			return render_template('404.html', current_user=current_user)
	return render_template('article.html', title=article.title, article=article, current_user=current_user)


# tagged articles
# includes continents (north america, south america, asia, etc.) and topics (international relations, wildlife, etc.)
@app.route('/tags/<requested_tag>', methods=['GET'])
def tags(requested_tag: str):
	# get requested tag as formatted string
	# for example 'North America' rather than 'north_america'
	if requested_tag not in url_to_tag_dict:
		print('error: tag not found')
		return redirect('/')
	formatted_tag = url_to_tag_dict[requested_tag]

	tagged_article_list = []
	for filename in os.listdir('articles/'):
		full_filename = os.path.join('articles/', filename)
		# only add to article list if it is a file
		if os.path.isfile(full_filename):
			art = load_article(filename[:-len('.json')])
			if art is None:
				print(f'tag({requested_tag}): error loading article {filename} with path {full_filename}')
				continue
			# only include articles with specified tag
			if requested_tag in art.tags:
				tagged_article_list.append(art)
	# sort tagged_article_list in descending order so that the most recent articles are towards front of list
	tagged_article_list.sort(key=lambda article: article.creation_date_epoch, reverse=True)

	tagged_articles = [tagged_article_list[i:i + 3] for i in range(0, len(tagged_article_list), 3)]
	try:
		return render_template('tag.html', title=formatted_tag, tagged_articles=tagged_articles,
		                       current_user=current_user)
	except TemplateError:
		print('error rendering tag', requested_tag)
		return redirect('/')


@app.route('/edit_tags/', methods=['GET', 'POST'])
def edit_tags(new_tag: str = None):
	if not current_user.is_authenticated:
		return render_template('403.html', current_user=current_user)
	form = TagEditForm()
	if form.validate_on_submit():
		# edit tag list
		global url_to_tag_dict
		url_name = form.new_tag.data.lower().replace(' ', '_')
		if url_name in url_to_tag_dict:
			flash('That tag already exists, please pick a different one.', 'danger')
		else:
			url_to_tag_dict[url_name] = form.new_tag.data
			update_articleform_tag_choices()

			with open('app_files/tags.json', 'w') as f:
				f.write(json.dumps(url_to_tag_dict, indent=4))
			return redirect(url_for('dashboard'))
	# serve form page
	return render_template('edit_tags.html', form=form, current_user=current_user)


@app.route('/directory/', methods=['GET'])
def directory():
	article_list = get_all_articles()
	return render_template('directory.html', article_list=article_list, current_user=current_user)


@app.route('/edit/<article_id>.html', methods=['GET', 'POST'])
@app.route('/edit/', methods=['GET', 'POST'])
def edit(article_id: str = None):
	if not current_user.is_authenticated:
		return render_template('403.html', current_user=current_user)
	form = ArticleForm()
	if form.validate_on_submit():
		if article_id is None:
			article_id = str(randint(0, 2 ** 31))
		title = form.title.data
		author = form.author.data
		# only update creation date if we are creating a new article
		# if editing an existing article keep date the same
		if os.path.isfile(f'articles/{article_id}.json'):
			art = load_article(article_id)
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
			cover_image_name = os.path.join('static/article_img', unique_filename)
			if os.path.exists(cover_image_name):
				os.remove(cover_image_name)
			cover_image.save(cover_image_name)  # save uploaded image
			cover_image_name = '/' + cover_image_name
		else:
			# this is an existing article and the image is not being edited
			# keep cover_image_name the same
			temp = load_article(article_id)
			cover_image_name = temp.cover_image_name

		cover_image_alt_text = form.cover_image_alt_text.data
		cover_image_source = form.cover_image_source.data
		citation = form.citation.data
		tags = form.article_tags.data
		article = Article(title=title, author=author, article_id=article_id, creation_date_epoch=creation_date_epoch,
		                  edit_date_epoch=edit_date_epoch, tags=tags, cover_image_name=cover_image_name,
		                  cover_image_alt_text=cover_image_alt_text, cover_image_source=cover_image_source,
		                  citation=citation, body=body)
		save_article(article)
		return redirect(url_for('articles', article_id=article.article_id))
	article = None
	if article_id is None or not os.path.isfile(f'articles/{str(article_id)}.json'):
		# article_id is None -> called /edit/ (new article)
		# not os.path.isfile(f'articles/{article_id}.json') -> called /edit/<article_id> on nonexistent article_id
		article_id = str(randint(0, 2 ** 31))
		form.cover_image.validators = [FileRequired(),
		                               FileAllowed(['jpg', 'png', 'jpeg', 'webp'], 'Please upload a jpg or png file')]
	else:
		# article already exists (editing existing article) -> populate form
		article = load_article(article_id)

		form = ArticleForm(obj=article)
		form.cover_image.validators = [FileAllowed(['jpg', 'png', 'jpeg', 'webp'], 'Please upload a jpg or png file')]
		form.article_tags.data = article.tags
	return render_template('edit.html', form=form, article=article, article_id=article_id, current_user=current_user)


@app.route('/login/', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		username = form.username.data
		password = form.password.data
		remember_me = form.remember_me.data

		if not os.path.isfile(f'users/{username}.txt'):
			# user tried to log in to account that doesn't exist
			flash('Invalid username or password.', 'danger')
			return render_template('login.html', form=form, current_user=current_user)
		else:
			with open(f'users/{username}.txt', 'r') as f:
				# get hashed_password line from user file
				hashed_password = f.readlines()[1]
			user = load_user(username)

			if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
				flash('Invalid username or password.', 'danger')
				return render_template('login.html', form=form, current_user=current_user)
			login_user(user, remember=remember_me)
			return redirect(url_for('dashboard'))
	return render_template('login.html', form=form, current_user=current_user)


@app.route('/logout/', methods=['GET', 'POST'])
def logout():
	logout_user()
	return redirect('/')


@app.route('/new_user/<new_user_otp>', methods=['GET', 'POST'])
def new_user(new_user_otp):
	with open('new_user_otp_list.txt', 'r') as f:
		new_user_otp_list = f.read().split('\n')

	if new_user_otp not in new_user_otp_list:
		return render_template('403.html', current_user=current_user)

	form = NewUserForm()
	if form.validate_on_submit():
		email = form.email.data
		name = form.name.data
		username = form.username.data
		password = form.password.data

		if os.path.isfile(f'users/{username}.txt'):
			# user tried to create username that already exists
			flash('That username already exists, please pick a different one.', 'danger')
			form.username.data = ''
		else:
			user_filename = f'users/{username}.txt'
			hashed_password = hash_password(password)
			with open(user_filename, 'w') as f:
				f.write(username + '\n' + hashed_password + '\n' + name + '\n' + email)

			# automatically log in user after they create an account
			user = load_user(username)
			login_user(user)

			with open('new_user_otp_list.txt', 'r') as f:
				old_content = f.read().split('\n')
			old_content.remove(str(new_user_otp))
			new_content = '\n'.join(old_content)
			with open('new_user_otp_list.txt', 'w') as f:
				f.write(new_content)

			return redirect(url_for('dashboard'))
	return render_template('new_user.html', form=form, otp=new_user_otp, current_user=current_user)


@app.route('/dashboard/', methods=['GET'])
def dashboard():
	if not current_user.is_authenticated:
		return render_template('403.html', current_user=current_user)
	return render_template('dashboard.html', article_list=get_all_articles(), current_user=current_user)


@app.route('/about_us/', methods=['GET'])
def about_us():
	return render_template('about_us.html', title='About Us')


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


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5010, debug=False)

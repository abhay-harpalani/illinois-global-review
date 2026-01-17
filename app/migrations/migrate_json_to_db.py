import datetime
import json
from pathlib import Path
from typing import Tuple

import psycopg
from dotenv import dotenv_values
from psycopg2.extras import DictCursor


def migrate_tags(cur: DictCursor) -> int:
	tag_ct = 0
	with open('../app_files/tags.json', 'r') as f:
		data = json.load(f)
		assert isinstance(data, dict)
		slug_to_display_name = data

		for slug, display_name in slug_to_display_name.items():
			cur.execute(
				"INSERT INTO tags (slug, display_name) VALUES (%s, %s)",
				(str(slug), str(display_name))
			)
			tag_ct += 1
	return tag_ct


def migrate_articles(cur: DictCursor) -> Tuple[int, int]:
	article_ct = 0
	article_tag_ct = 0
	for file_path in Path('../articles').iterdir():
		if not file_path.is_file():
			continue
		with open(file_path, 'r') as f:
			data = json.load(f)
			# load attributes from json file
			title = str(data['title'])
			author = str(data['author'])
			article_id = str(data['article_id'])
			creation_date_epoch = datetime.datetime.fromtimestamp(int(data['creation_date_epoch']))
			edit_date_epoch = datetime.datetime.fromtimestamp(int(data['edit_date_epoch']))
			cover_image_name = str(data['cover_image_name'])
			cover_image_alt_text = str(data['cover_image_alt_text'])
			cover_image_source = str(data['cover_image_source'])
			citation = str(data['citation'])
			body = str(data['body'])

			cur.execute(
				"""INSERT INTO articles (article_id, title, author, creation_date_epoch, edit_date_epoch,
                                         cover_image_path, cover_image_alt_text, cover_image_source, citation, body)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
				(article_id, title, author, creation_date_epoch, edit_date_epoch, cover_image_name,
				 cover_image_alt_text, cover_image_source, citation, body)
			)
			article_ct += 1

			tags = data['tags']
			for slug in tags:
				cur.execute(
					"INSERT INTO article_tags (article_id, tag_slug) VALUES (%s, %s)",
					(article_id, slug)
				)
				article_tag_ct += 1
	return article_ct, article_tag_ct

db_username = dotenv_values('../.env')['POSTGRES_USERNAME']
db_password = dotenv_values('../.env')['POSTGRES_PASSWORD']

with psycopg.connect(f'dbname=igr user={db_username} password={db_password}') as conn:
	with conn.cursor() as cur:
		tag_ct = migrate_tags(cur)
		article_ct, article_tag_ct = migrate_articles(cur)

		print(f'Migrated {tag_ct} tags, {article_ct} articles, and {article_tag_ct} article tags')

import os
import json

# for filename in os.listdir("articles/"):
for filename in ["1199794256.txt"]:
	full_filename = os.path.join("articles/", filename)
	# only add to article list if it is a file that ends in .txt
	if os.path.isfile(full_filename) and full_filename[-len(".txt"):] == ".txt":
		with open(full_filename, 'r') as f:
			lines = []
			for i in range(9):
				# [:-1] removes \n from end of line
				lines.append(f.readline()[:-1])
			# body can have newlines in it so we just read the rest of the file
			lines.append(f.read())
			print(lines)

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

			article_dict = {
				'title': title,
				'author': author,
				'article_id': article_id,
				'creation_date_epoch': creation_date_epoch,
				'edit_date_epoch': edit_date_epoch,
				'tags': tags,
				'cover_image_name': cover_image_name,
				'cover_image_alt_text': cover_image_alt_text,
				'cover_image_source': cover_image_source,
				'citation': '',
				'body': body,
			}
			with open(full_filename[:-len('.txt')] + '.json', 'w') as f2:
				f2.write(json.dumps(article_dict, indent=4))
			# print(json.loads())


# import json
# from dataclasses import dataclass
# from typing import List
#
# @dataclass
# class Article:
# 	title: str
# 	author: str
# 	# id of the article, visible in URL
# 	article_id: str
# 	# creation date of the article represented as unix epoch time
# 	creation_date_epoch: str
# 	# date that the article was last edited
# 	edit_date_epoch: str
# 	# tags for the article (north america, europe, asia, africa, south america, oceania)
# 	# abbreviated to "na", "sa", "eu", "af", "as", "oc"
# 	tags: List[str]
# 	# name of cover image so that /static/img/{cover_image_name} points to image location (includes file extension)
# 	cover_image_name: str
# 	# alt text for image for screen readers
# 	cover_image_alt_text: str
# 	# source text under image
# 	cover_image_source: str
# 	# citation at bottom of page, has different format when viewing article page
# 	citation: str
# 	# content of the article formatted with html tags
# 	body: str
#
# article_path = 'articles/2115185602.json'
#
# with open(article_path, 'r') as f:
# 	print(json.load(f, object_hook=lambda d: Article(**d)))
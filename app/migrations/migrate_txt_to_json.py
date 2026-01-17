import os
import json

tags_dict = {
	'na': 'north_america',
	'eu': 'europe',
	'as': 'asia',
	'af': 'africa',
	'sa': 'south_america',
	'oc': 'oceania',
}

# for filename in ['39965563.json']:
for filename in os.listdir('articles/'):
	full_filename = os.path.join('articles/', filename)
	# only add to article list if it is a file that ends in .txt
	if os.path.isfile(full_filename) and full_filename[-len('.json'):] == '.json':
		data = ""
		with open(full_filename, 'r') as f:
			data = json.load(f)
			n = []
			for t in data['tags']:
				if t in tags_dict:
					n.append(tags_dict[t])
				else:
					print(f"file: {filename} - tag: {t}")
			data['tags'] = n

		with open(full_filename, 'w') as f:
			f.write(json.dumps(data, indent=4))

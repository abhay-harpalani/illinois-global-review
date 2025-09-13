import random


# makes one-time passcode which can be used to make a single account
# no args -> assume running in ./app
def make_otp(path_to_otp_list='new_user_otp_list.txt'):
	with open(path_to_otp_list, "a") as f:
		new_otp = str(random.randint(0, 2 ** 31))
		f.write(new_otp + "\n")
		return new_otp


if __name__ == '__main__':
	make_otp()

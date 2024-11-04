import random

with open("new_user_otp_list.txt", "a") as f:
	new_otp = str(random.randint(0, 2**31)) + "\n"
	f.write(new_otp)

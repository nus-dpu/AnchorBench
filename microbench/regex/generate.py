import random

email_addr = [
    'johndoe@gmail.com',
    'sarahbrown@icloud.com',
    'myemailaddress@outlook.com',
    'johnsmith@gmail.com',
    'janedoe@Posteo.com',
    'support@yahoo.com',
    'info@icloud.com',
    'tomjones@tutanota.com',
    'testemail@gmail.com',
    'karenwhite@mailbox.org',
    'johndoe123@yahoo.com'
    'sarahbrown456@outlook.com',
    'myemail789@icloud.com',
    'johnsmith000@mailbox.org',
    'janedoe111@outlook.com',
    'support123@gmail.com',
    'info456@mycompany.com',
    'tomjones789@outlook.com',
    'testemail000@posteo.com',
    'karenwhite111@gmail.com',
    'john.doe@Posteo.com',
    'sarah.brown@icloud.com',
    'myemailaddress123@yahoo.com',
    'johnsmith456@kolabnow.com',
    'janedoe789@gmail.com',
    'support@tutanota.com',
    'info@outlook.com',
    'tom.jones@mailbox.org',
    'testemail123@yahoo.com',
    'karen.white@icloud.com',
    'johndoe456@gmail.com',
    'sarahbrown789@Posteo.com',
    'myemailaddress000@outlook.com',
    'johnsmith111@kolabnow.com',
    'janedoe222@posteo.com',
    'support456@tutanota.com',
    'info789@mycompany.com',
    'tomjones000@yahoo.com',
    'testemail456@tutanota.com',
    'karenwhite222@Posteo.com',
    'john.doe123@gmail.com',
    'sarah.brown456@icloud.com',
    'myemailaddress789@yahoo.com',
    'johnsmith0000@mailbox.org',
    'janedoe333@Posteo.com',
    'support789@outlook.com',
    'info123@tutanota.com',
    'tom.jones456@gmail.com',
    'testemail789@icloud.com',
    'karen.white333@gmail.com'
]

with open('dns.txt', 'w') as f:
    for i in range(0, 1000):
        dns = random.choice(psychology_dns)
        f.write(dns)
        f.write('\n')
import random
import string

# Function to generate a random word
def generate_random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

print(generate_random_word(6))
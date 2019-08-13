import string
def encode_dict(encryption_key):
    encoding={}
    alphabet = string.ascii_lowercase + " "
    for i in range(len(alphabet)):
        encoding[alphabet[i]]=(i+encryption_key)%27
    return encoding

def caesar(message,encryption_key):
    # return the encoded message as a single string!
    alphabet = string.ascii_lowercase + " "

# create `letters` here!
    letters={}
    for i in range(len(alphabet)):
        letters[i]=alphabet[i]
    encoded_message = ''
    # use the function in Step 2 to get the encoding dictionary
    encoding = encode_dict(encryption_key)
    for char in message:
        encoded_message+=letters[encoding[char]]
    return encoded_message
    # your code is here
    # for each letter in message, get the encoded letter
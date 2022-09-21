"""
Naive implementation of a password based Caesar cipher.

Useful methods:
---------------
password_caesar_cipher
"""

def password_caesar_cipher(message, password, encrypt, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    """
    Extension of the classic Caesar Cipher.
    Characters will be rotated based on the characters in the given password.
    Cipher is linear and can easily be broken if len(msg) >> len(pw).

    Parameters:
    -----------
    message : str
        The message to encrypt/decrypt
    password : str
        The password to use for encryption/decryption
    encrypt : bool
        Mode of method: Encryption or Decryption
    alphabet : str, defaults to "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        The alphabet to use

    Returns:
    --------
    str
        The encrypted/decrypted message
    """
    alpha_length = len(alphabet)
    # Create a dictionary {char : index}
    positions = {alphabet[i] : i for i in range(alpha_length)}
    # Rotate left during encryption and rotate right during decryption
    direction = 1 if encrypt else -1
    enc_msg = ""
    password_idx = 0
    for char in message:
        # Get next char from password
        password_character = password[password_idx % len(password)]
        # Calculate index of encrypted/decrypted char
        enc_pos = (positions[char] + direction * positions[password_character]) % alpha_length
        # Append char to encrypted message
        enc_msg += alphabet[enc_pos]
        password_idx += 1
    return enc_msg

def read_from_file(path):
    """
    Read the file 'path' and return its content.
    """
    with open(path, encoding="utf8") as file:
        return file.read()

def write_to_file(path, data):
    """
    Write 'data' to file 'path', overwriting existing content if present.
    """
    with open(path, "w", encoding="utf8") as file:
        file.write(data)

def create_full_alphabet(password, message):
    """
    Create a full alphabet with lower and upper case letters
    as well as numbers and all special characters used in
    both password 'pw' and message 'msg'.
    """
    full_abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(set(char for char in full_abc+password+message))

def simple_demonstration():
    """
    Simple demonstration on a short message
    """
    password = "PASSWORD"
    message = "STRENGGEHEIMEINFORMATIONEN"
    print(f"{message=}")
    enc_msg = password_caesar_cipher(message, password, True)
    print(f"{enc_msg=}")
    dec_msg = password_caesar_cipher(enc_msg, password, False)
    print(f"{dec_msg=}")

def advanced_demonstration():
    """
    Demonstration with a longer text.
    """
    # Let's use our own doc string and
    # a pretty obscure password
    password = r"<--\/ER4-->"
    documentation = password_caesar_cipher.__doc__
    print(f"\nDocumentation of our encryption function:\n{documentation}\n")

    # We need more than only upper case letters to represent our documentation
    abc = create_full_alphabet(password, documentation)
    print(f"Using alphabet:\n{repr(abc)}\n")

    # Encrypt our documentation string
    enc_docs = password_caesar_cipher(documentation, password, True, abc)
    print(f"\nEncrypted documentation:\n{enc_docs}\n")

    # Decrypt it again
    dec_docs = password_caesar_cipher(enc_docs, password, False, abc)
    # Print messages so we can see what was done
    print(f"\nDecrypted documentation:\n{dec_docs}\n")

def file_demonstration(file_name):
    """
    Let us now read and encrypt an entire file
    full of highly interesting lorem ipsum
    """
    ori_path = file_name + ".txt"
    enc_path = file_name + "_enc.txt"
    dec_path = file_name + "_dec.txt"

    # Read original file
    lorem_ipsum = read_from_file(ori_path)
    password = "Secret Roman Business"
    # Create suitable alphabet
    abc = create_full_alphabet(password, lorem_ipsum)

    # Encrypt and write to encrypted file
    write_to_file(enc_path, password_caesar_cipher(lorem_ipsum, password, True, abc))
    # Retrieve encrypted content from file
    enc_lorem_ipsum = read_from_file(enc_path)
    # Decrypt and write to decrypted file
    write_to_file(dec_path, password_caesar_cipher(enc_lorem_ipsum, password, False, abc))

    # Check if encryption and decryption was successful
    ori_content = read_from_file(ori_path)
    enc_content = read_from_file(enc_path)
    dec_content = read_from_file(dec_path)
    if ori_content != enc_content and ori_content == dec_content:
        print("Encrypted content is different from" + \
            "and decrypted content is equal to " + \
            "original content as intended!")
    else:
        print("Encryption/Decryption failed.")

def main():
    """
    Runs our demonstration methods
    """
    simple_demonstration()
    advanced_demonstration()
    file_demonstration("lorem_ipsum")

if __name__ == "__main__":
    main()

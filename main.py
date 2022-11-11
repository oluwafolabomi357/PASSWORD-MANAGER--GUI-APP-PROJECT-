from tkinter import *
from tkinter import messagebox
from random import choice, shuffle, randint
import rsa
import pyperclip


# -------------------------------------------Encryption Keys---------------------------------------------------- #
import os

publicKey, privateKey = rsa.newkeys(512)


def save_keys():
    with open("private_key.txt", "w") as prk:
        if os.path.getsize("private_key.txt") == 0:
            prk.write(f"{privateKey.save_pkcs1().decode('utf8')}")
    with open("public_key.txt", "w") as puk:
        if os.path.getsize("public_key.txt") == 0:
            puk.write(f"{publicKey.save_pkcs1().decode('utf8')}")
    return "saved keys successfully"
# ------------------------------------------------- SAVE PASSWORD --------------------------------------------------- #


def save_entries():

    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if len(website) == 0 or len(password) == 0 or len(email) == 0:

        messagebox.showinfo(title="Oops", message="Please make sure you haven't left any fields empty!")
    else:
        is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered:\n"
                                                              f" \nWebsite: {website}\n"

                                                              f"\nPassword: {password}\n"
                                                              f"\nEmail: {email}\n"

                                                              f"\nIs it Ok to save?")
        if is_ok:
            with open("data.txt", "a") as data_file:
                # --------------------- Password Encryption---------------------- #
                # generate public and private keys with
                # rsa.newkeys method,this method accepts
                # key length as its parameter
                # key length should be at least 16

                # this is the string that we will be encrypting
                password_key = password_entry.get()
                message = f"{password_key}"

                # rsa.encrypt method is used to encrypt
                # string with public key string should be
                # encoded to byte string before encryption
                # with encode method
                enc_message = rsa.encrypt(message.encode(), publicKey)

                print("original string: ", message)
                print("encrypted string: ", enc_message)

                # the encrypted message can be decrypted
                # with ras.decrypt method and private key
                # decrypt method returns encoded byte string,
                # use decode method to convert it to string
                # public key cannot be used for decryption
                print(enc_message)
                import base64
                enc_message = base64.b64encode(enc_message).decode()
                print(enc_message)
                data_file.write(email + ";|" + website + ";|" + f"{enc_message}\n")
                website_entry.delete(0, END)
                password_entry.delete(0, END)
                email_entry.delete(0, END)
                return f"{enc_message}"

    test_entry = "saved entries successfully"
    return test_entry
# ------------------------------------------- PASSWORD GENERATOR -----------------------------------------------------#


def generate_password():

    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
               'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['@', '#', '$', '*', '(', ')', '[', ']', '/', '?',
               '%', '&', '|']
    password_letters = [choice(letters) for _ in range(randint(5, 8))]
    password_numbers = [choice(numbers) for _ in range(randint(2, 4))]
    password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
    password_list = password_letters + password_numbers + password_symbols
    shuffle(password_list)
    password = "".join(password_list)
    password_entry.insert(0, password)
    pyperclip.copy(password)

    test_password = "saved password successfully"
    return test_password


# ---------------------------------------------------- UI SETUP ----------------------------------------------------- #


window = Tk()
window.title("Welcome to the Fol_ls' Industry")
window.config(bg='#65A8E1', padx=20, pady=20)
canvas = Canvas(height=200, width=200)
logo_img = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_img)
canvas.grid(row=0, column=1)

# Labels

website_label = Label(text="Website:", bg='#65A8E1')
website_label.grid(row=1, column=0)
email_label = Label(text="Email/Username:", bg='#65A8E1')
email_label.grid(row=2, column=0)
password_label = Label(text="Password:", bg='#65A8E1')
password_label.grid(row=3, column=0)

# Entries

website_entry = Entry(width=52)
website_entry.grid(row=1, column=1, columnspan=2)
website_entry.focus()
email_entry = Entry(width=52)
email_entry.grid(row=2, column=1, columnspan=2)
email_entry.insert(0, "you@gmail.com")
password_entry = Entry(width=34, show="*", fg="red")
password_entry.grid(row=3, column=1)

# Buttons
generate_password_button = Button(text="Generate password", command=generate_password,
                                  bg='#65A8E1', fg="black", activebackground="blue")

generate_password_button.grid(row=3, column=2)
add_button = Button(text="Add", width=43, command=save_entries, bg='#65A8E1', fg="black",
                    activebackground="blue")
add_button.grid(row=5, column=1, columnspan=2)
Encrypt = Button(text="Encrypt Password", width=43, command=save_keys, bg='#65A8E1', fg="black",
                 activebackground="blue")
Encrypt.grid(row=4, column=1, columnspan=2)

window.mainloop()

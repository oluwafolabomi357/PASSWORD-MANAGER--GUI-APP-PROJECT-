from tkinter import *
from tkinter import messagebox
import rsa
import pyperclip

page = Tk()
page.title("Get Password")
page.config(padx=20, pady=20)
canvas = Canvas(height=200, width=200)
logo_img = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_img)
canvas.grid(row=0, column=1)

# Entries
web_entry = Entry(width=52)
web_entry.grid(row=1, column=1, columnspan=2)
web_entry.focus()
em_entry = Entry(width=52)
em_entry.grid(row=2, column=1, columnspan=2)
em_entry.insert(0, "")
# Label
web_label = Label(text="Website:")
web_label.grid(row=1, column=0)
em_label = Label(text="Email/Username:")
em_label.grid(row=2, column=0)


def decrypt():
    import base64
    with open(r"C:\Users\USER\Desktop\ATC__project\password-manager-start\data.txt", "rb") as text:

        for i in text:
            data = i.split(";|".encode())
            print(data)
            enc_message = bytes(base64.b64decode(data[2]))
            print(enc_message)
            if em_entry.get() == data[0].decode() and web_entry.get() == data[1].decode():

                with open(r"C:\Users\USER\Desktop\ATC__project\password-manager-start\private_key.txt", "r") as prk2:
                    privateKey = prk2.read().encode()
                    privateKey = rsa.PrivateKey.load_pkcs1(privateKey)
                    dec_message = rsa.decrypt(enc_message, privateKey).decode('utf8')
                    print(dec_message)
                    messagebox.showinfo(title="Welcome to the fol_ls'", message=f"Your password is {dec_message}")
                    print("decrypted string: ", dec_message)

                    pyperclip.copy(dec_message)
                    return
            elif em_entry.get() == data[0].decode() or web_entry.get() == data[1].decode():
                continue

        messagebox.showerror(title="Input Error!", message="Pls,ensure the login details entered\n"
                                                           " are those needed to fetch password.")

    return "passwords decrypted successfully"


Get_Pass_button = Button(text="Get password", command=decrypt)
Get_Pass_button.grid(row=3, column=1)
page.mainloop()

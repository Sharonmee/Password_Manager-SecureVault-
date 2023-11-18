#!/usr/bin/env python3
## GUI package
import hashlib
import binascii
import tkinter as tk
from tkinter import messagebox
import os
## import user interface package
from tkinter import *
## import package for use image in the project
from PIL import ImageTk, Image  # (pillow)
## alertDialog
from tkinter import messagebox
## import the encryption and decryption package
from cryptography.fernet import Fernet


print("this script is working")


def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    stored_password = (salt + pwdhash).decode('ascii')
    return stored_password


def check_user():
    with open('app_password', 'r') as file:
        lines = file.readlines()

    for line in lines:
        if line.strip() == username:
            return True
    return False


## signp GUI code
def signup_gui():
    window_signup = tk.Tk()  # creates the main window
    window_signup.title("SIGN UP ")
    window_signup.config(bg="#581845")
    window_signup.geometry("800x500")
    window_signup.resizable(True, True)

    #icon_path = "icon_path = /usr/share/pixmaps/python3.x/python.xpm"

    #icon = tk.PhotoImage(file=icon_path)
    #window_signup.iconphoto(True, icon)

    #logo_path = os.path.expanduser("~/Documents/project1/Password_Manager-SecureVault/logo.jpeg")
    #logo = Image.open(logo_path)
    #logo = logo.resize((320, 210))
    #photo = ImageTk.PhotoImage(logo)
    #label_image = Label(window_signup, image=photo)
    #label_image.place(x=50, y=140)

    welcome_text = Label(window_signup, text="Welcome there", bg="#353535", fg="white", width=10)
    welcome_text.pack(side=LEFT, padx=70, pady=10)
    welcome_text_style = ("Comic Sans Ms", 15, "bold")
    welcome_text.configure(font=welcome_text_style)

    text_enter_username = Label(window_signup, text="Enter your username")
    text_enter_username.configure(font='Helvetica 12 bold', fg="black")
    text_enter_username.pack(padx=90, pady=20)
    text_enter_username_style = ("Comic Sans Ms", 15, "bold")
    text_enter_username.configure(font=text_enter_username_style)

    username_entry = Entry(window_signup, width=30)
    username_entry.pack(side=LEFT, padx=72, pady=7)
    username_entry_style = ("Arial",)
    username_entry.configure(font=username_entry_style)

    text_enter_password = Label(window_signup, text="Enter your password")
    text_enter_password.configure(font='Helvetica 12 bold', fg="black")
    text_enter_password.pack(padx=90, pady=40)
    text_enter_password_style = ("Comic Sans Ms", 15, "bold")
    text_enter_password.configure(font=text_enter_password_style)

    password_entry = Entry(window_signup, width=30)
    password_entry.pack(side=LEFT, padx=82, pady=9)
    password_entry_style = ("Arial",)
    password_entry.configure(font=password_entry_style)

    text_enter_confirm_password = Label(window_signup, text="Confirm your password")
    text_enter_confirm_password.configure(font='Helvetica 12 bold', fg="black")
    text_enter_confirm_password.pack(padx=90, pady=40)
    text_enter_confirm_password_style = ("Comic Sans Ms", 15, "bold")
    text_enter_confirm_password.configure(font=text_enter_confirm_password_style)

    confirm_password_entry = Entry(window_signup, width=30)
    confirm_password_entry.pack(side=LEFT, padx=82, pady=9)
    confirm_password_entry_style = ("Arial",)
    confirm_password_entry.configure(font=confirm_password_entry_style)

    def signup():
        global username
        username = username_entry.get()
        global password
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if len(username) == 0 and len(password) == 0 and len(confirm_password) == 0:
            messagebox.showerror("Error", "All fields must be filled")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        password_encrypt = hash_password(password)

        if not check_user():
            password_file = open('app_password', 'a')
            password_file.write('\n' + username + ':' + password_encrypt)
            password_file.close()
        else:
            messagebox.showerror("User already exists")

        window_signup.destroy()

    signup_button = Button(window_signup, text="Sign up", width=20, bg="pink", command=signup)
    signup_button.pack()
    signup_button.place(x=450, y=280)
    signup_button_style = ("Centaur", 17, "bold")
    signup_button.configure(font=signup_button_style)

    print("script is working")

    window_signup.mainloop()


signup_gui()

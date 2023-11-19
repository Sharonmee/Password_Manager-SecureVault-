#!/usr/bin/env python3
import hashlib
import binascii
import tkinter as tk
from tkinter import messagebox
import os
from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
from cryptography.fernet import Fernet

print("this script is working")

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    stored_password = (salt + pwdhash).decode('ascii')
    return stored_password

def check_user(username):
    try:
        with open('app_password', 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        open('app_password', 'w').close()
        return False
    
    for line in lines:
        if line.strip().split(':')[0] == username:
            return True
    return False



#add password code
def addpasswordgui():
    window_addpassword = tk.Tk()
    window_addpassword.title("ADD PASSWORD")
    window_addpassword.config(bg="#581845")
    window_addpassword.geometry("920x500")
    window_addpassword.resizable(False, False)

    addpassword_text = Label(window_addpassword, text="Add Password Here", bg="#353535", fg="white", width=19)
    addpassword_text.pack(side=LEFT)
    addpassword_text_style = ("Comic Sans Ms", 40, "bold")
    addpassword_text.configure(font=addpassword_text_style)




    text_enter_acctype = Label(window_addpassword, text="Enter Account type you wish to save ")
    text_enter_acctype.configure(font='Helvetica 12 bold', fg="black")
    text_enter_acctype.pack(padx=90, pady=20)
    text_enter_acctype.place(x=610, y=20)
    text_enter_acctype_style = ("Comic Sans Ms", 15, "bold")
    text_enter_acctype.configure(font=text_enter_acctype_style)

    acctype_entry = Entry(window_addpassword, width=30)
    acctype_entry.pack(side=LEFT, padx=72, pady=7)
    acctype_entry.place(x=630, y=70)
    acctype_entry_style = ("Arial",)
    acctype_entry.configure(font=acctype_entry_style)

    text_enter_accusername = Label(window_addpassword, text="Enter Account username or email ")
    text_enter_accusername.configure(font='Helvetica 12 bold', fg="black")
    text_enter_accusername.pack(padx=91, pady=20)
    text_enter_accusername.place(x=610, y=120)
    text_enter_accusername_style = ("Comic Sans Ms", 15, "bold")
    text_enter_accusername.configure(font=text_enter_accusername_style)

    accusername_entry = Entry(window_addpassword, width=30)
    accusername_entry.pack(side=LEFT, padx=72, pady=7)
    accusername_entry.place(x=630, y=170)
    accusername_entry_style = ("Arial",)
    accusername_entry.configure(font=accusername_entry_style)

    text_enter_accpassword = Label(window_addpassword, text="Enter your password")
    text_enter_accpassword.configure(font='Helvetica 12 bold', fg="black")
    text_enter_accpassword.pack(padx=91, pady=40)
    text_enter_accpassword.place(x=610, y=220)
    text_enter_accpassword_style = ("Comic Sans Ms", 15, "bold")
    text_enter_accpassword.configure(font=text_enter_accpassword_style)

    accpassword_entry = Entry(window_addpassword, width=30, show="*")
    accpassword_entry.pack(side=LEFT, padx=82, pady=9)
    accpassword_entry.place(x=630, y=270)
    accpassword_entry_style = ("Arial",)
    accpassword_entry.configure(font=accpassword_entry_style)

    

    def save():
        global username
        username =accusername_entry.get()
        global password
        password = accpassword_entry.get()
        global acctype
        acctype = acctype_entry.get()

        if len(username) == 0 or len(password) == 0 :
            messagebox.showerror("Error", "All fields must be filled")
            return
        
        ##update code to check if that account already exists
        
        #now i create a file to store the username and password,in the future i'll save it on a database

        accpassword_encrypt = hash_password(password)
        accpassword_file = open('accdetails', 'a')
        accpassword_file.write('\n'+ acctype + ':' + username + ':' + accpassword_encrypt) 
        messagebox.showinfo("Save successful")
        accpassword_file.close()
        window_addpassword.destroy()
        homepage_gui()

    save_button = Button(window_addpassword, text="SAVE", width=10, bg="pink", command=save)
    save_button.pack()
    save_button.place(x=630, y=350)
    save_button_style = ("Centaur", 17, "bold")
    save_button.configure(font=save_button_style)

    window_addpassword.mainloop()


def deletepassword():
    window_deletepassword = tk.Tk()
    window_deletepassword.title("DELETE PASSWORD")
    window_deletepassword.config(bg="#581845")
    window_deletepassword.geometry("920x500")
    window_deletepassword.resizable(False, False)

    deletepassword_text = Label(window_deletepassword, text="Delete Password Here", bg="#353535", fg="white", width=19)
    deletepassword_text.pack(side=LEFT)
    deletepassword_text_style = ("Comic Sans Ms", 40, "bold")
    deletepassword_text.configure(font=deletepassword_text_style)

    text_enter_accname = Label(window_deletepassword, text="Enter account you want to delete")
    text_enter_accname.configure(font='Helvetica 12 bold', fg="black")
    text_enter_accname.pack(padx=90, pady=20)
    text_enter_accname.place(x=610, y=20)
    text_enter_accname_style = ("Comic Sans Ms", 15, "bold")
    text_enter_accname.configure(font=text_enter_accname_style)

    accname_entry = Entry(window_deletepassword, width=30)
    accname_entry.pack(side=LEFT, padx=72, pady=7)
    accname_entry.place(x=630, y=70)
    accname_entry_style = ("Arial",)
    accname_entry.configure(font=accname_entry_style)




    def delete():
        accname = accname_entry.get()

        if len(accname) == 0:
            messagebox.showerror("Error", "Account name field must be filled")
            return
        
        try:
            with open('accdetails', 'r') as file:
                lines = file.readlines()
        
            with open('accdetails', 'w') as file:
                for line in lines:
                    if line.split('acctype') == accname and line.split('username') == username:
                        file.write(line)
        
            messagebox.showinfo("Delete successful")
            accname_entry.delete(0, END)
            window_deletepassword.destroy()
            homepage_gui()
        except FileNotFoundError:
            messagebox.showerror("Error", "File not found")

    delete_button = Button(window_deletepassword, text="DELETE", width=10, bg="pink", command=delete)
    delete_button.pack()
    delete_button.place(x=630, y=350)
    delete_button_style = ("Centaur", 17, "bold")
    delete_button.configure(font=delete_button_style)

    window_deletepassword.mainloop()


    
def showdetails_gui():
    window_showdetails = tk.Tk()
    window_showdetails.title("Saved account details")
    window_showdetails.config(bg="#581845")
    window_showdetails.geometry("920x500")
    window_showdetails.resizable(False, False)

    showpassword_text = Label(window_showdetails, text="Show saved account details", bg="#353535", fg="white", width=25)
    showpassword_text.pack(side=LEFT)
    showpassword_text_style = ("Comic Sans Ms", 30, "bold")
    showpassword_text.configure(font=showpassword_text_style)

    text_enter_accname = Label(window_showdetails, text="Enter account you want to view")
    text_enter_accname.configure(font='Helvetica 12 bold', fg="black")
    text_enter_accname.pack(padx=90, pady=20)
    text_enter_accname.place(x=610, y=20)
    text_enter_accname_style = ("Comic Sans Ms", 15, "bold")
    text_enter_accname.configure(font=text_enter_accname_style)

    accname_entry = Entry(window_showdetails, width=30)
    accname_entry.pack(side=LEFT, padx=72, pady=7)
    accname_entry.place(x=600, y=170)
    accname_entry_style = ("Arial",)
    accname_entry.configure(font=accname_entry_style)

    def showdetails():
        acctype = accname_entry.get()

        if len(acctype) == 0:
            messagebox.showerror("Error", "Account name field must be filled")
            return
        
        try:
            with open('accdetails', 'r') as file:
                lines = file.readlines()

            found = False

            for line in lines:
                parts = line.split(':')
                if parts[0] == acctype:
                    messagebox.showinfo("Account Details", f"Username/email:{parts[1]} \nPassword: {password}")
                    found = True
                    window_showdetails.destroy()
                    homepage_gui()
                    break

            if not found:
                messagebox.showerror("Account details not found , try again")
                window_showdetails.destroy()
                homepage_gui()

        except FileNotFoundError:
            messagebox.showerror("Error", "File not found")
            window_showdetails.destroy()
            homepage_gui()


    show_details_button = Button(window_showdetails, text="Show Details", width=15, bg="lightblue", command=showdetails)
    show_details_button.pack()
    show_details_button.place(x=630, y=400)
    show_details_button_style = ("Centaur", 14, "bold")
    show_details_button.configure(font=show_details_button_style)
   

        






        
## window that has the addpassword button showsaved button and delete saved details button

def homepage_gui():
    window_homepage = tk.Tk()
    window_homepage.title("Home Page")
    window_homepage.config(bg="#581845")
    window_homepage.geometry("910x600")
    window_homepage.resizable(False, False)


    welcome_text = Label(window_homepage, text="What do you wish to do", bg="#353535", fg="white", width=20)
    welcome_text.pack(side=LEFT)
    welcome_text_style = ("Comic Sans Ms", 40, "bold")
    welcome_text.configure(font=welcome_text_style)


    text = Label(window_homepage, text="Choose an option")
    text.configure(font='Helvetica 12 bold', fg="black")
    text.pack(padx=90, pady=20)
    text.place(x=610, y=20)
    text_style = ("Comic Sans Ms", 25, "bold")
    text.configure(font=text_style)


    def add_close():
        window_homepage.destroy()
        addpasswordgui()
    
    #add password button, opens the add button window
    add_button = Button(window_homepage, text="Add password", width=20, bg="pink", command=add_close)
    add_button.pack()
    add_button.place(x=530, y=150)
    add_button_style = ("Centaur", 17, "bold")
    add_button.configure(font=add_button_style)
    
    def show_close():
        window_homepage.destroy()
        showdetails_gui()

    show_button = Button(window_homepage, text="Show saved passwords", width=20, bg="pink", command=show_close)#change the command here to show
    show_button.pack()
    show_button.place(x=530, y=250)
    show_button_style = ("Centaur", 17, "bold")
    show_button.configure(font=show_button_style)
    

    def delete_close():
        window_homepage.destroy()
        deletepassword()

    delete_button = Button(window_homepage, text="Delete password", width=20, bg="pink", command=delete_close)#change the command here to delete
    delete_button.pack()
    delete_button.place(x=530, y=350)
    delete_button_style = ("Centaur", 17, "bold")
    delete_button.configure(font=delete_button_style)
    
    #logout_button = Button(window_homepage, text="Log out", width=10, bg="red", command=)

    window_homepage.mainloop()
def signup_gui():
    window_signup = tk.Tk()
    window_signup.title("SIGN UP")
    window_signup.config(bg="#581845")
    window_signup.geometry("810x500")
    window_signup.resizable(False, False)

    welcome_text = Label(window_signup, text="Welcome there", bg="#353535", fg="white", width=15)
    welcome_text.pack(side=LEFT)
    welcome_text_style = ("Comic Sans Ms", 40, "bold")
    welcome_text.configure(font=welcome_text_style)

    text_enter_username = Label(window_signup, text="Enter your username")
    text_enter_username.configure(font='Helvetica 12 bold', fg="black")
    text_enter_username.pack(padx=90, pady=20)
    text_enter_username.place(x=610, y=20)
    text_enter_username_style = ("Comic Sans Ms", 15, "bold")
    text_enter_username.configure(font=text_enter_username_style)

    username_entry = Entry(window_signup, width=30)
    username_entry.pack(side=LEFT, padx=72, pady=7)
    username_entry.place(x=530, y=70)
    username_entry_style = ("Arial",)
    username_entry.configure(font=username_entry_style)

    text_enter_password = Label(window_signup, text="Enter your password")
    text_enter_password.configure(font='Helvetica 12 bold', fg="black")
    text_enter_password.pack(padx=91, pady=20)
    text_enter_password.place(x=610, y=120)
    text_enter_password_style = ("Comic Sans Ms", 15, "bold")
    text_enter_password.configure(font=text_enter_password_style)

    password_entry = Entry(window_signup, width=30, show="*")
    password_entry.pack(side=LEFT, padx=82, pady=9)
    password_entry.place(x=530, y=170)
    password_entry_style = ("Arial",)
    password_entry.configure(font=password_entry_style)

    text_enter_confirm_password = Label(window_signup, text="Confirm your password")
    text_enter_confirm_password.configure(font='Helvetica 12 bold', fg="black")
    text_enter_confirm_password.pack(padx=90, pady=40)
    text_enter_confirm_password.place(x=610, y=220)
    text_enter_confirm_password_style = ("Comic Sans Ms", 15, "bold")
    text_enter_confirm_password.configure(font=text_enter_confirm_password_style)

    confirm_password_entry = Entry(window_signup, width=30, show="*")
    confirm_password_entry.pack(side=LEFT, padx=82, pady=9)
    confirm_password_entry.place(x=530, y=270)
    confirm_password_entry_style = ("Arial",)
    confirm_password_entry.configure(font=confirm_password_entry_style)

    def signup():
        global username
        username = username_entry.get()
        global password
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if len(username) == 0 or len(password) == 0 or len(confirm_password) == 0:
            messagebox.showerror("Error", "All fields must be filled")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if not check_user(username):
            password_encrypt = hash_password(password)
            password_file = open('app_password', 'a')
            password_file.write('\n' + username + ':' + password_encrypt)
            messagebox.showinfo("Sign Up successful")
            password_file.close()
            window_signup.destroy()
            homepage_gui()
            
        else:
            messagebox.showerror("User already exists")
            window_signup.destroy()

    signup_button = Button(window_signup, text="Sign up", width=20, bg="pink", command=signup)
    signup_button.pack()
    signup_button.place(x=530, y=350)
    signup_button_style = ("Centaur", 17, "bold")
    signup_button.configure(font=signup_button_style)

    print("script is working")
    window_signup.mainloop()

def login_gui():
    window_login = tk.Tk()
    window_login.title("Login UP")
    window_login.config(bg="#581845")
    window_login.geometry("810x500")
    window_login.resizable(False, False)

    #welcome_text = Label(window_login, text="Login Here", bg="#353535", fg="white")
    welcome_text = Label(window_login, text="Login Here", bg="#353535", fg="white", width=15)
    welcome_text.pack(side=LEFT)
    welcome_text_style = ("Comic Sans Ms", 40, "bold")
    welcome_text.configure(font=welcome_text_style)

    text_enter_username = Label(window_login, text="Enter your username")
    text_enter_username.configure(font='Helvetica 12 bold', fg="black")
    text_enter_username.pack(padx=90, pady=20)
    text_enter_username.place(x=610, y=20)
    text_enter_username_style = ("Comic Sans Ms", 15, "bold")
    text_enter_username.configure(font=text_enter_username_style)

    username_entry = Entry(window_login, width=30)
    username_entry.pack(side=LEFT, padx=72, pady=7)
    username_entry.place(x=530, y=70)
    username_entry_style = ("Arial",)
    username_entry.configure(font=username_entry_style)

    text_enter_password = Label(window_login, text="Enter your password")
    text_enter_password.configure(font='Helvetica 12 bold', fg="black")
    text_enter_password.pack(padx=91, pady=20)
    text_enter_password.place(x=610, y=120)
    text_enter_password_style = ("Comic Sans Ms", 15, "bold")
    text_enter_password.configure(font=text_enter_password_style)

    password_entry = Entry(window_login, width=30, show="*")
    password_entry.pack(side=LEFT, padx=82, pady=9)
    password_entry.place(x=530, y=170)
    password_entry_style = ("Arial",)
    password_entry.configure(font=password_entry_style)

    text_enter_confirm_password = Label(window_login, text="Confirm your password")
    text_enter_confirm_password.configure(font='Helvetica 12 bold', fg="black")
    text_enter_confirm_password.pack(padx=90, pady=40)
    text_enter_confirm_password.place(x=610, y=220)
    text_enter_confirm_password_style = ("Comic Sans Ms", 15, "bold")
    text_enter_confirm_password.configure(font=text_enter_confirm_password_style)

    confirm_password_entry = Entry(window_login, width=30, show="*")
    confirm_password_entry.pack(side=LEFT, padx=82, pady=9)
    confirm_password_entry.place(x=530, y=270)
    confirm_password_entry_style = ("Arial",)
    confirm_password_entry.configure(font=confirm_password_entry_style)

    def login():
        global username
        username = username_entry.get()
        global password
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()

        if len(username) == 0 or len(password) == 0 or len(confirm_password) == 0:
            messagebox.showerror("Error", "All fields must be filled")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if check_user(username):
            messagebox.showinfo("Login Successful")
            window_login.destroy()
            homepage_gui()
        else:
            messagebox.showinfo("User does not exist")
            window_login.destroy()
            signup_gui()

    login_button = Button(window_login, text="Login button", width=10, bg="pink", command=login)
    login_button.pack()
    login_button.place(x=530, y=350)
    login_button_style = ("Centaur", 17, "bold")
    login_button.configure(font=login_button_style)

    window_login.mainloop()

login_gui()



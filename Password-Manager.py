from curses import tigetnum
from doctest import master
from functools import partial
from msilib.schema import File
import tkinter
from tkinter.font import NORMAL
import customtkinter
import string
import secrets
import sqlite3
import hashlib
import random
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from tkinter import messagebox
import shutil
from os import path
from tkinter import filedialog



customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")


class App(customtkinter.CTk):

    WIDTH = 570
    HEIGHT = 580

    def __init__(self):
        super().__init__()

        ''' General Attributes '''

        # General attributes of the main window
        self.geometry(f"{App.WIDTH}x{App.HEIGHT}")
        self.title("Password-Generator")

        # Columns and Rows of the main window
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        global password_score
        password_score = 0.0


        ''' Functions Section '''

        def slide(var):
            self.pass_length_value_label = customtkinter.CTkLabel(master=self.options_frame, text=int(self.pass_length_slider.get()))
            self.pass_length_value_label.grid(row=4, column=2, padx=0)
        
        def password_strength(*args):
            
            password = self.input.get()

            if len(password) < 6:
                password_score =+ 0.0
                
                for i in password:
                    if i.islower():
                        password_score += 0.0
                    elif i.isupper():
                        password_score += 0.1
                    elif i.isdigit():
                        password_score += 0.1
                    else:
                        password_score += 0.1

            if len(password) >= 6 and len(password) < 10:
                password_score =+ 0.1

                for i in password:
                    if i.islower():
                        password_score += 0.0
                    elif i.isupper():
                        password_score += 0.1
                    elif i.isdigit():
                        password_score += 0.1
                    else:
                        password_score += 0.1

            if len(password) >= 10:
                password_score =+ 0.2

                for i in password:
                    if i.islower():
                        password_score += 0.0
                    elif i.isupper():
                        password_score += 0.1
                    elif i.isdigit():
                        password_score += 0.1
                    else:
                        password_score += 0.1


            self.password_strength.set(password_score)
            

        
        def clicked():
            
            if (self.capital_letter_var.get() == "on") and (self.numbers_var.get() == "on") and (self.symbols_var.get() == "on"):
                pass_source = string.ascii_letters + string.digits + string.punctuation
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.ascii_uppercase)
                password += secrets.choice(string.digits)
                password += secrets.choice(string.punctuation)

                for i in range(0, (int(self.pass_length_slider.get()) - 4)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "off") and (self.numbers_var.get() == "on") and (self.symbols_var.get() == "on"):
                pass_source = string.ascii_lowercase + string.digits + string.punctuation
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.digits)
                password += secrets.choice(string.punctuation)

                for i in range(0, (int(self.pass_length_slider.get()) - 3)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "off") and (self.numbers_var.get() == "off") and (self.symbols_var.get() == "on"):
                pass_source = string.ascii_lowercase + string.punctuation
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.punctuation)

                for i in range(0, (int(self.pass_length_slider.get()) - 2)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "off") and (self.numbers_var.get() == "off") and (self.symbols_var.get() == "off"):
                pass_source = string.ascii_lowercase
                password = ''

                for i in range(0, int(self.pass_length_slider.get())):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "on") and (self.numbers_var.get() == "on") and (self.symbols_var.get() == "off"):
                pass_source = string.ascii_letters + string.digits
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.digits)
                password += secrets.choice(string.ascii_uppercase)

                for i in range(0, (int(self.pass_length_slider.get()) - 3)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "on") and (self.numbers_var.get() == "off") and (self.symbols_var.get() == "off"):
                pass_source = string.ascii_letters
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.ascii_uppercase)

                for i in range(0, (int(self.pass_length_slider.get()) - 2)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "on") and (self.numbers_var.get() == "off") and (self.symbols_var.get() == "on"):
                pass_source = string.ascii_letters + string.punctuation
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.punctuation)
                password += secrets.choice(string.ascii_uppercase)

                for i in range(0, (int(self.pass_length_slider.get()) - 3)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)

            elif (self.capital_letter_var.get() == "off") and (self.numbers_var.get() == "on") and (self.symbols_var.get() == "off"):
                pass_source = string.ascii_lowercase + string.digits
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.digits)

                for i in range(0, int(self.pass_length_slider.get())):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().choice(pass_list)
                password = ''.join(pass_list)
                
                self.password_field_entry.delete(0, tkinter.END)
                self.password_field_entry.insert(0, password)


        ''' GUI Section '''

        # Password Frame
        self.password_frame = customtkinter.CTkFrame(master=self, height=45, corner_radius=10)
        self.password_frame.grid(row=0, column=0, padx=50, pady=20, sticky="nswe")

        # Password Field
        self.input = tkinter.StringVar()
        self.password_field_entry = customtkinter.CTkEntry(master=self.password_frame, textvariable=self.input, width=450, height=35, corner_radius=7)
        self.password_field_entry.grid(padx=10, pady=10, sticky="nswe")
        self.input.trace('w',password_strength)

        # Options Frames
        self.options_frame = customtkinter.CTkFrame(master=self, corner_radius=10)
        self.options_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.options_frame.grid(row=1, column=0, padx=50, pady=50, sticky="nswe")

        #Info Frame
        self.info_frame = customtkinter.CTkFrame(master=self.options_frame)
        self.info_frame.grid(row=0, column=1, columnspan=2, rowspan=4, pady=10, padx=18, sticky="e")
        self.info_frame.rowconfigure(2, weight=1)
        self.info_frame.columnconfigure(0, weight=1)

        self.info_label = customtkinter.CTkLabel(master=self.info_frame,
                                                   text="Check boxes if you want your\n" +
                                                        "password to include them.\n" +
                                                        "Pull the slider to your desired \n" +
                                                        "password length." ,
                                                   height=100,
                                                   corner_radius=6,
                                                   fg_color=("white", "gray38"),
                                                   justify=tkinter.LEFT)
        self.info_label.grid(column=0, row=0, sticky="nwe", padx=15, pady=15)

        self.info_label = customtkinter.CTkLabel(master=self.info_frame, text="Password Strength:")
        self.info_label.grid(row=1, column=0, padx=15, sticky="w")

        # Password Strength
        self.password_strength = customtkinter.CTkProgressBar(master=self.info_frame)
        self.password_strength.set(0)
        self.password_strength.grid(row=2, padx=20, pady=10)

        # Checkbox
        self.symbols_var = tkinter.StringVar()
        self.symbols_check = customtkinter.CTkCheckBox(master=self.options_frame, text="Symbols", variable=self.symbols_var, onvalue="on", offvalue="off")
        self.symbols_check.deselect()
        self.symbols_check.grid(row=1, column=0, padx=18, pady=12, sticky="w")

        self.numbers_var = tkinter.StringVar()
        self.numbers_check = customtkinter.CTkCheckBox(master=self.options_frame, text="Numbers", variable=self.numbers_var, onvalue="on", offvalue="off")
        self.numbers_check.deselect()
        self.numbers_check.grid(row=2, column=0, padx=18, pady=12, sticky="w")

        self.capital_letter_var = tkinter.StringVar()
        self.capital_letter_check = customtkinter.CTkCheckBox(master=self.options_frame, text="Capital Letters", variable=self.capital_letter_var, onvalue="on", offvalue="off")
        self.capital_letter_check.deselect()
        self.capital_letter_check.grid(row=3, column=0, padx=18, pady=12, sticky="w")

        # Slider Definition
        self.slider_definition = customtkinter.CTkLabel(master=self.options_frame, text="Password Length (4 - 30): ")
        self.slider_definition.grid(row=4, column=0, padx=18, sticky="w")

        # Password Length Slider
        self.pass_length_slider = customtkinter.CTkSlider(master=self.options_frame, width=150, from_=4, to=30, command=slide)
        self.pass_length_slider.grid(row=4, column=1, columnspan=1, padx=0, pady=15, sticky="w")
        self.pass_length_slider.set(4)

        # Generate Button
        self.generate_button = customtkinter.CTkButton(master=self.options_frame, height=35, text="Generate Password", command=clicked)
        self.generate_button.place(relx=0.5, rely=0.75, anchor=tkinter.CENTER)

        # Password Manager Button
        self.password_manager = customtkinter.CTkButton(master=self.options_frame, height=35, width=400, text="Password Vault",
                                                        fg_color=("#006B3C"), hover_color=("#004B49"), command=self.Password_Manager)
        self.password_manager.place(relx=0.5, rely=0.92, anchor=tkinter.CENTER)

    
    
    ''' Password Manager '''

    def Password_Manager(self): # Creates a top level window which is the password manager window

        '''General Part'''
        password_manager = customtkinter.CTkToplevel(self)
        password_manager.geometry("300x200")
        password_manager.title("Password-Manager")
        


        '''Database Section'''
        with sqlite3.connect("Password_Vault.db") as database: # Creates or opens the Password_Vault database
            cursor = database.cursor()

        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL);
        """) # Creates masterpassword table and its properties in Password_Vault database if it does not exist

        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        webapp TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL);
        """) # Creates vault table and its properties in Password_Vault database if it does not exist


        '''Functions Section'''

        def Add_Entry_Window(): # This is a top level window in which the user can add it's records to the database
            add_entry_window = customtkinter.CTkToplevel()
            add_entry_window.geometry("540x250")
            add_entry_window.title("Add Entry")

            def Save_Entry():
                if len(webapp_entry.get()) == 0 or len(user_entry.get()) == 0 or len(pass_entry.get()) == 0: # This will prevents the user to leave an entry empty and warns them to not to
                    messagebox.showinfo(parent=add_entry_window, title="Oops!", message="Please make sure you haven't left any field empty!!!")
                else: # This will ask the user (if there is no empty field) in a popup window if they want to save the record or not
                    is_ok = messagebox.askokcancel(parent=add_entry_window, title=webapp_entry.get(), message="These are the details entered:\n"
                                                                                                                f"Username: {user_entry.get()}\n"
                                                                                                                f"Password: {pass_entry.get()}\n"
                                                                                                                "Is it ok to save?")
                    if is_ok:# If the user prompts the addition of the record this block will run
                        # The next three lines will get the user's inputs and save them into their variables
                        webapp = webapp_entry.get()
                        username = user_entry.get()
                        password = pass_entry.get()

                        # Next four lines will add the entries into the database
                        insert_fields = """INSERT INTO vault(webapp,username,password)
                        VALUES(?, ?, ?)"""
                        cursor.execute(insert_fields, (webapp, username, password))
                        database.commit()

                        # Next three lines will clear the user inputs from entries
                        webapp_entry.delete(0, tkinter.END)
                        user_entry.delete(0, tkinter.END)
                        pass_entry.delete(0, tkinter.END)

                        Vault_Window() # Refreshes the Vault window

            def totally_random(): # This function will create a completely random password and insert it into the password field
                pass_source = string.ascii_letters + string.digits + string.punctuation
                password = secrets.choice(string.ascii_lowercase)
                password += secrets.choice(string.ascii_uppercase)
                password += secrets.choice(string.digits)
                password += secrets.choice(string.punctuation)

                for i in range(0, random.randrange(4, 7)):
                    password += secrets.choice(pass_source)

                pass_list = list(password)
                secrets.SystemRandom().shuffle(pass_list)
                password = ''.join(pass_list)
                
                pass_entry.delete(0, tkinter.END)
                pass_entry.insert(0, password)

            webapp_label = customtkinter.CTkLabel(master=add_entry_window, text="Website/Application:")
            webapp_label.grid(row=0, column=0, padx=20, pady=15)
            user_label = customtkinter.CTkLabel(master=add_entry_window, text="Username/E-mail:")
            user_label.grid(row=1, column=0, padx=20, pady=15)
            pass_label = customtkinter.CTkLabel(master=add_entry_window, text="Password:")
            pass_label.grid(row=2, column=0, padx=20, pady=15)

            webapp_entry = customtkinter.CTkEntry(master=add_entry_window, corner_radius=7)
            webapp_entry.grid(row=0, column=1, columnspan=3, padx=20, pady=15, sticky="ew")
            webapp_entry.focus_set()
            user_entry = customtkinter.CTkEntry(master=add_entry_window, corner_radius=7)
            user_entry.grid(row=1, column=1, columnspan=3, padx=20, pady=15, sticky="ew")
            pass_entry = customtkinter.CTkEntry(master=add_entry_window, corner_radius=7)
            pass_entry.grid(row=2, column=1, columnspan=2, padx=20, pady=15)
            randompass_button = customtkinter.CTkButton(master=add_entry_window, fg_color="#8031A7", hover_color="#2E1A47", text="Generate", command=totally_random)
            randompass_button.grid(row=2, column=3, padx=20, pady=15)

            save_button = customtkinter.CTkButton(master=add_entry_window, fg_color="#006B3C", hover_color="#004B49", text="Save", command= Save_Entry)
            save_button.grid(row=3, column=0, columnspan=4, padx=20, pady=15, sticky="ew")

        def Hash_Password(input): # This function will encrypt the entries
            hash = hashlib.sha256(input)
            hash = hash.hexdigest()

            return hash


        '''GUI and some functionality'''

        
        def First_Window(): # First time login window which gets the user password for the first time
            m_password1_label = customtkinter.CTkLabel(master=password_manager, text="Create manster-password: ")
            m_password1_label.configure(anchor=tkinter.CENTER)
            m_password1_label.pack()

            m_password1_entry = customtkinter.CTkEntry(master=password_manager, corner_radius=7, show="*") # First entry of the password
            m_password1_entry.pack()

            m_password2_label = customtkinter.CTkLabel(master=password_manager, text="Re-enter manster-password: ")
            m_password2_label.configure(anchor=tkinter.CENTER)
            m_password2_label.pack()

            m_password2_entry = customtkinter.CTkEntry(master=password_manager, corner_radius=7, show="*") # Asks for the password for second time to prompt the equality
            m_password2_entry.pack()

            def Save_Password(): # If the entered passwords are the same it will save it into the database
                if m_password1_entry.get() == m_password2_entry.get(): # Checks for the sameness
                    hashed_password = Hash_Password(m_password1_entry.get().encode('utf-8')) # Encrypts the password entered

                    insert_password = """INSERT INTO masterpassword(password)
                    VALUES(?)"""
                    cursor.execute(insert_password, [(hashed_password)]) # Inserts the password into the database
                    database.commit()

                    Vault_Window() # Opens vault main window
                else: # If the entries aren't the same this code will be executed
                    m_password1_entry.delete(0, tkinter.END) # Clears the entry
                    m_password2_entry.delete(0, tkinter.END)
                    wrong_password_label = customtkinter.CTkLabel(master=password_manager, text="Does Not Match!", text_color="red") # Warns the user for not being match
                    wrong_password_label.place(relx=0.5, rely=0.9, anchor=tkinter.CENTER)
                    

            save_button = customtkinter.CTkButton(master=password_manager, text="Save", width=100, command=Save_Password) # This button calls the function to save password
            save_button.pack(pady=20)
        
        def Login_Window(): # Opens the login window and gets the user password
            m_password_label = customtkinter.CTkLabel(master=password_manager, text="Enter your manster-password: ")
            m_password_label.place(relx=0.5, rely=0.3, anchor=tkinter.CENTER)

            m_password_entry = customtkinter.CTkEntry(master=password_manager, width=210, corner_radius=7, show="*") # Asks for the user's input (AKA Password)
            m_password_entry.place(relx=0.5, rely=0.5, anchor=tkinter.CENTER)
            m_password_entry.focus_set()

            def Get_Master_Password(): # Calls the database to get the right password
                Check_Hashed_Password = Hash_Password(m_password_entry.get().encode('utf-8')) # Encrypts the user entry in order to be checked later
                cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(Check_Hashed_Password)])
                return cursor.fetchall()

            def Check_Password():
                match = Get_Master_Password()

                if match:
                    Vault_Window() # If the entry matches with the master password it will open the vault window
                else: # It will clear the entry and display "Wrong Password!" if the entry and master password does not match
                    m_password_entry.delete(0, tkinter.END)
                    m_password_label = customtkinter.CTkLabel(master=password_manager, text="Wrong Password!", text_color="red")
                    m_password_label.place(relx=0.5, rely=0.1, anchor=tkinter.CENTER)


            save_button = customtkinter.CTkButton(master=password_manager, text="Enter", width=100, command=Check_Password)
            save_button.place(relx=0.5, rely=0.8, anchor=tkinter.CENTER)
        
        def Vault_Window(): # Password vault main window
            for widget in password_manager.winfo_children(): # Will close other child windows
                widget.destroy()
            password_manager.geometry("615x590")

            def Remove_Entry(input): # Deletes an entry after it is called
                sure = messagebox.askokcancel(parent=password_manager, title="Delete Record", message="Are you sure you want to delete this record?")
                if sure:# If the user prompts the deletion of the record this block will run
                    cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
                    database.commit()
                    Vault_Window() # Refreshes vault window
            
            def Copy_Entry(entry): # Copies an entry
                password_manager.clipboard_clear()
                password_manager.clipboard_append(entry)
                password_manager.update()

            def BackUp(): # Gets a backup of database
                source = path.realpath("Password_Vault.db") # Places the database location
                destination = filedialog.askdirectory(parent=password_manager) # Asks for the user to select the destination

                if destination == '': # It will prevent the error for "No destination"
                    return

                else:
                    shutil.copy(source, destination) # This will copy the source file into the destination


            def Restore():
                source = filedialog.askdirectory(parent=password_manager) + "/Password_Vault.db" #This will ask for the file location
                destination = os.getcwd() # Gets the current path of the app

                if source == '/Password_Vault.db': # Prevents error if there is no path
                    return
                else:
                    shutil.copy(source, destination) # This will copy the source file into the destination
                    Vault_Window() # Refreshes vault window


            page_title = customtkinter.CTkLabel(master=password_manager, text_font=(25), text="Password Vault") # This is the title of the main vault window
            page_title.grid(row=0, column=0, columnspan=4, pady=10, sticky="ew")

            add_button = customtkinter.CTkButton(master=password_manager, 
                                                    text="Add",
                                                    width=100,
                                                    corner_radius=15,
                                                    command=Add_Entry_Window)
            add_button.grid(row=1, column=0, padx=5, columnspan=1, pady=15, sticky="w") # It opens a window to add new records

            backup_button = customtkinter.CTkButton(master=password_manager, 
                                                    text="Backup", 
                                                    fg_color="#17462d", 
                                                    hover_color="#0b2316", 
                                                    corner_radius=15, 
                                                    width=100, 
                                                    command=BackUp)
            backup_button.grid(row=1, column=0, columnspan=1, padx=88, pady=15) # This button runs the backup function

            restore_button = customtkinter.CTkButton(master=password_manager, 
                                                    text="Restore", 
                                                    fg_color="#b26b00", 
                                                    hover_color="#352000", 
                                                    corner_radius=15, 
                                                    width=100, 
                                                    command=Restore)
            restore_button.grid(row=1, column=0, columnspan=4, padx=0, pady=15) # This button runs the Restore function

            vault_main_frame = customtkinter.CTkFrame(master=password_manager, fg_color="#485962") # This is the frame for titles of the user/pass table
            vault_main_frame.grid(row=2, columnspan=4, pady=5, padx=5, sticky="nswe")

            web_app_label = customtkinter.CTkLabel(master=vault_main_frame, text="Website/App") # A title of the table
            web_app_label.grid(row=0, column=0, padx=20)
            username_label = customtkinter.CTkLabel(master=vault_main_frame, text="Username") # A title of the table
            username_label.grid(row=0, column=1, padx=20)
            password_label = customtkinter.CTkLabel(master=vault_main_frame, text="Password") # A title of the table
            password_label.grid(row=0, column=2, padx=20)
            
            vault_pass_frame = customtkinter.CTkFrame(master=password_manager) # Creates an expandable frame to put the records in it
            vault_pass_frame.grid(row=3, column=0, columnspan=4, padx=5)

            cursor.execute("SELECT * FROM vault") # Searches for all the records in database
            if cursor.fetchall() != None: # If there is records it will run this block
                i = 0 # Sets the value of i to 0
                while True: # Creates an infinite loop
                    cursor.execute("SELECT * FROM vault") # Gets all the records
                    array = cursor.fetchall() # puts each record into the array variable

                    if array == []: # If array is empty it just passes
                        pass_frame = customtkinter.CTkFrame(master=vault_pass_frame) # creates a frame for each record
                        pass_frame.grid(row=i+3, columnspan=4, pady=5, padx=5, sticky="nswe")

                        webapp_label = customtkinter.CTkLabel(master=pass_frame, text="No Record") # Gets the first value of the record (webapp)
                        webapp_label.grid(row=0, column=0, padx=20, sticky="nswe")

                        user_label = customtkinter.CTkLabel(master=pass_frame, text="No Record") # Gets the second value of the record (Username)
                        user_label.grid(row=0, column=1, padx=20, sticky="nswe")
                        
                        pass_label = customtkinter.CTkLabel(master=pass_frame, text="No Record") # Gets the third value of the record (Password)
                        pass_label.grid(row=0, column=2, padx=20, sticky="nswe")

                        delete_button = customtkinter.CTkButton(master=pass_frame,
                                                                    text="Nothing",
                                                                    width=50,
                                                                    fg_color="darkred")
                        delete_button.grid(row=0, column=3, sticky="w") # Creates a delete button for each record
                    
                    else: # If array has value it will create these properties for it
                        pass_frame = customtkinter.CTkFrame(master=vault_pass_frame) # creates a frame for each record
                        pass_frame.grid(row=i+3, columnspan=4, pady=5, padx=5, sticky="nswe")

                        webapp_label = customtkinter.CTkLabel(master=pass_frame, text=(array[i][1])) # Gets the first value of the record (webapp)
                        webapp_label.grid(row=0, column=0, padx=20, sticky="nswe")

                        user_label = customtkinter.CTkLabel(master=pass_frame, text=array[i][2]) # Gets the second value of the record (Username)
                        user_label.grid(row=0, column=1, padx=20, sticky="nswe")
                        user_copy_button = customtkinter.CTkButton(master=pass_frame, 
                                                                    text="📑",
                                                                    text_font=("Times New Roman",-20),
                                                                    width=20, height=20, 
                                                                    fg_color="#343638", hover_color= "#4f4f4f", 
                                                                    border_width=0, 
                                                                    command=partial(Copy_Entry, array[i][2]))
                        user_copy_button.grid(row=0, column=1, sticky="e", padx=10) # Creates a copy button for each username
                        
                        pass_label = customtkinter.CTkLabel(master=pass_frame, text=(array[i][3])) # Gets the third value of the record (Password)
                        pass_label.grid(row=0, column=2, padx=20, sticky="nswe")
                        pass_copy_button = customtkinter.CTkButton(master=pass_frame, 
                                                                    text="📑",
                                                                    text_font=("Times New Roman",-20),
                                                                    width=20, height=20, 
                                                                    fg_color="#343638", hover_color= "#4f4f4f", 
                                                                    border_width=0, 
                                                                    command=partial(Copy_Entry, array[i][3]))
                        pass_copy_button.grid(row=0, column=2, sticky="e", padx=10) # Creates a copy button for each password

                        delete_button = customtkinter.CTkButton(master=pass_frame,
                                                                    text="Delete",
                                                                    width=50,
                                                                    fg_color="darkred",
                                                                    command=partial(Remove_Entry, array[i][0]))
                        delete_button.grid(row=0, column=3, sticky="w") # Creates a delete button for each record

                    i += 1 # Increases i value by 1 each time

                    cursor.execute("SELECT * FROM vault")
                    if (len(cursor.fetchall()) <= i): # When the value of i is equal or greater than the records it will stop the while loop
                        break




        cursor.execute("SELECT * FROM masterpassword") # Checks the masterpassword table to see if it is empty or not
        
        if cursor.fetchall(): # if the massterpassword table has a record it will call the login window
            Login_Window()
        else: # If the masterpassword entry is empty it will call the first window to ask the user to enter a master password
            First_Window()

if __name__ == "__main__":
    app = App()
    app.mainloop()

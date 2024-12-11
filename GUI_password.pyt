import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import string
import secrets
from cryptography.fernet import Fernet

# Génération de la clé de chiffrement pour la sauvegarde sécurisée
key = Fernet.generate_key()
cipher = Fernet(key)

# === Fonction de génération de mot de passe ===
def generate_password():
    try:
        length = int(password_length_var.get())
        use_uppercase = uppercase_var.get()
        use_digits = digits_var.get()
        use_special = special_var.get()

        characters = string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_digits:
            characters += string.digits
        if use_special:
            characters += string.punctuation

        if length < 6:
            raise ValueError("6 caractères requis")
        if length > 20:
            raise ValueError("20 caractères maximum")

        password = ''.join(secrets.choice(characters) for _ in range(length))
        result_var.set(password)
        progress_bar['value'] = length * 5  # Animation visuelle pour la longueur
    except ValueError as e:
        messagebox.showerror("Erreur", str(e))

# === Fonction d'évaluation de la robustesse ===
def evaluate_password():
    password = password_input.get()
    if not password:
        messagebox.showerror("Erreur", "Un mot de passe est requis.")
        return

    length = len(password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    score = length * (has_upper + has_lower + has_digit + has_special)
    details = []

    if not has_upper:
        details.append("Ajouter des majuscules.")
    if not has_lower:
        details.append("Ajouter des minuscules.")
    if not has_digit:
        details.append("Ajouter des chiffres.")
    if not has_special:
        details.append("Ajouter des caractères spéciaux.")

    if score >= 40:
        strength = "Très fort"
    elif score >= 30:
        strength = "Fort"
    elif score >= 20:
        strength = "Faible"
    else:
        strength = "Très faible"

    details_text = "\n".join(details) if details else " Bon équilibre."
    result_var.set(f"Robustesse : {strength}\n{details_text}")

# === Fonction pour copier le mot de passe dans le presse-papier ===
def copy_to_clipboard():
    password = result_var.get()
    if not password:
        messagebox.showerror("Erreur", "Pas de mot de passe à copier.")
        return
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()
    messagebox.showinfo("Succès", "Mot de passe copié dans le presse-papier !")

# === Fonction pour enregistrer le mot de passe dans un fichier sécurisé ===
def save_password():
    password = result_var.get()
    if not password:
        messagebox.showerror("Erreur", "Pas de mot de passe à enregistrer.")
        return

    encrypted = cipher.encrypt(password.encode())
    with open("passwords.txt", "ab") as file:
        file.write(encrypted + b"\n")
    messagebox.showinfo("Succès", "Mot de passe enregistré en toute sécurité.")

# === Interface Tkinter avec ttkbootstrap ===
root = ttk.Window(themename="solar")  # Utilisation du thème Solar
root.title("Gestion des mots de passe")
root.geometry("600x400")
root.resizable(True, True)

# Variables
password_length_var = ttk.StringVar(value="12")
uppercase_var = ttk.BooleanVar(value=True)
digits_var = ttk.BooleanVar(value=True)
special_var = ttk.BooleanVar(value=True)
password_input = ttk.StringVar()
result_var = ttk.StringVar()

# Widgets principaux
ttk.Label(root, text="🔒 Gestion des Mots de Passe", font=("Helvetica", 20, "bold"), anchor="center").pack(pady=10)

frame = ttk.Frame(root, padding=10)
frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

# Génération de mot de passe
ttk.Label(frame, text="Longueur du mot de passe :").grid(row=0, column=0, sticky="w", pady=5)
ttk.Entry(frame, textvariable=password_length_var, width=5).grid(row=0, column=1, sticky="w", pady=5)

ttk.Checkbutton(frame, text="Inclure des majuscules", variable=uppercase_var).grid(row=1, column=0, columnspan=2, sticky="w")
ttk.Checkbutton(frame, text="Inclure des chiffres", variable=digits_var).grid(row=2, column=0, columnspan=2, sticky="w")
ttk.Checkbutton(frame, text="Inclure des caractères spéciaux", variable=special_var).grid(row=3, column=0, columnspan=2, sticky="w")

ttk.Button(frame, text="Générer un mot de passe", command=generate_password).grid(row=4, column=0, columnspan=2, pady=10)

# ProgressBar pour animation visuelle
progress_bar = ttk.Progressbar(frame, length=200, mode="determinate", bootstyle=INFO)
progress_bar.grid(row=5, column=0, columnspan=2, pady=5)

# Analyse de mot de passe
ttk.Label(frame, text="Entrez un mot de passe :").grid(row=6, column=0, sticky="w", pady=5)
ttk.Entry(frame, textvariable=password_input, width=40).grid(row=6, column=1, pady=5)

ttk.Button(frame, text="Évaluer la robustesse", command=evaluate_password).grid(row=7, column=0, columnspan=2, pady=10)

# Résultat
ttk.Label(frame, text="Résultat :").grid(row=8, column=0, sticky="w", pady=5)
ttk.Entry(frame, textvariable=result_var, state="readonly", width=40).grid(row=8, column=1, pady=5)

ttk.Button(frame, text="Copier", command=copy_to_clipboard).grid(row=9, column=0, pady=10, sticky="w")
ttk.Button(frame, text="Enregistrer", command=save_password).grid(row=9, column=1, pady=10, sticky="e")

# Lancer l'application
root.mainloop()

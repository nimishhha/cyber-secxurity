import re

def check_password_strength(password):
    strength = 0
    suggestions = []

    if len(password) >= 8:
        strength += 1
    else:
        suggestions.append("Password too short (min 8 chars).")

    if re.search("[a-z]", password) and re.search("[A-Z]", password):
        strength += 1
    else:
        suggestions.append("Use both uppercase and lowercase letters.")

    if re.search("[0-9]", password):
        strength += 1
    else:
        suggestions.append("Add numbers.")

    if re.search("[!@#$%^&*(),.?\\\":{}|<>]", password):
        strength += 1
    else:
        suggestions.append("Add special characters.")

    if strength == 4:
        return "✅ Strong Password"
    elif strength == 3:
        return "⚠️ Moderate Password\nSuggestions: " + ", ".join(suggestions)
    else:
        return "❌ Weak Password\nSuggestions: " + ", ".join(suggestions)

if __name__ == "__main__":
    while True:
        pwd = input("Enter password (or 'exit' to quit): ")
        if pwd.lower() == "exit":
            break
        print(check_password_strength(pwd))

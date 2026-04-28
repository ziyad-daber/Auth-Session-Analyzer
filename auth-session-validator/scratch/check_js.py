
import os

file_path = r'c:\Users\hajar\Desktop\projet-mobile\auth-session-validator\frontend\app.js'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

open_braces = content.count('{')
close_braces = content.count('}')
open_parens = content.count('(')
close_parens = content.count(')')

print(f"Braces: {open_braces} open, {close_braces} close")
print(f"Parens: {open_parens} open, {close_parens} close")

# Basic check for unclosed template literals
ticks = content.count('`')
print(f"Backticks: {ticks}")

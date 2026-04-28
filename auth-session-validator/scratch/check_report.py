
file_path = r'c:\Users\hajar\Desktop\projet-mobile\auth-session-validator\frontend\app.js'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

content = "".join(lines[87:195]) # renderReport lines
open_braces = content.count('{')
close_braces = content.count('}')
print(f"renderReport: {open_braces} open, {close_braces} close")

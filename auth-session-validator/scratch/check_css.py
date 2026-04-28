
file_path = r'c:\Users\hajar\Desktop\projet-mobile\auth-session-validator\frontend\style.css'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

stack = []
for i, line in enumerate(lines):
    for char in line:
        if char == '{':
            stack.append(i + 1)
        elif char == '}':
            if not stack:
                print(f"Extra closing brace at line {i + 1}")
            else:
                stack.pop()

if stack:
    print(f"Unclosed braces opened at lines: {stack}")
else:
    print("No brace errors found in style.css")

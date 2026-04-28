
file_path = r'c:\Users\hajar\Desktop\projet-mobile\auth-session-validator\frontend\app.js'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

balance = 0
last_zero = 0
for i, line in enumerate(lines):
    balance += line.count('{')
    balance -= line.count('}')
    if balance == 0:
        last_zero = i + 1

print(f"Last line where balance was 0: {last_zero}")
print(f"File total lines: {len(lines)}")
if last_zero < len(lines):
    print(f"Problem starts after line {last_zero}")
    print(f"Next 5 lines:")
    for j in range(last_zero, min(last_zero + 5, len(lines))):
        print(f"{j+1}: {lines[j].strip()}")


file_path = r'c:\Users\hajar\Desktop\projet-mobile\auth-session-validator\frontend\app.js'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

balance = 0
for i, line in enumerate(lines):
    old_balance = balance
    balance += line.count('{')
    balance -= line.count('}')
    if balance != old_balance:
        # print(f"{i+1}: Balance {balance} | {line.strip()}")
        pass

print(f"Final Balance: {balance}")

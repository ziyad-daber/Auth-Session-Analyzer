import google.generativeai as genai
import os

api_key = "AIzaSyDtpsI5-ec4v6FE5iNwKleo1-PjV8FRty0"
genai.configure(api_key=api_key)

print("--- LISTE DES MODÈLES DISPONIBLES ---")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"Modèle: {m.name}")
except Exception as e:
    print(f"Erreur : {e}")

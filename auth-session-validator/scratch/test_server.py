import httpx
import asyncio

async def test_server_connection():
    url = "http://127.0.0.1:8888/login"
    print(f"[*] Tentative de connexion à {url}...")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data={"username": "admin", "password": "wrong_password"})
            print(f"[+] Succès ! Code: {resp.status_code}")
            print(f"[+] Réponse: {resp.text[:100]}")
    except Exception as e:
        print(f"[!] Échec: {e}")

if __name__ == "__main__":
    asyncio.run(test_server_connection())

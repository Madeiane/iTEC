Dupa ce am gasit codurile, l-am pus pe chat sa faca un cod sa le incerce pe toate.
```
import base64
from itertools import permutations

# Fragmentele tale (fără spații libere)
fragmente = [
    "Q1RGe3Mw",
    "zcl9xdT",
    "NzdF9tN",
    "YzFhbF8z",
    "bmcxbjM",
    "HN0M3J9"
]

def decripteaza_flag():
    print("Generăm permutările și căutăm flag-ul...\n")
    
    # permutations() ne dă toate cele 720 de variante posibile de aranjare
    for combo in permutations(fragmente):
        # Lipim fragmentele ca să formăm un singur șir
        b64_str = "".join(combo)
        
        try:
            # Încercăm să decodăm din Base64
            decoded_bytes = base64.b64decode(b64_str)
            # Convertim din bytes în text normal (UTF-8)
            decoded_text = decoded_bytes.decode('utf-8')
            
            # Verificăm dacă rezultatul are formatul clasic de flag
            if decoded_text.startswith("CTF{") and decoded_text.endswith("}"):
                print("✅ Am găsit combinația corectă!")
                print("-" * 40)
                print(f"Șirul Base64 final: {b64_str}")
                print(f"🚩 Flag-ul tău este: {decoded_text}")
                print("-" * 40)
                return # Oprim execuția după ce am găsit flag-ul
                
        except Exception:
            # Dacă decodarea eșuează (șir invalid sau caractere ciudate), ignorăm varianta
            continue

    print("❌ Nu am găsit niciun flag valid. Verifică dacă ai copiat corect fragmentele!")

if __name__ == "__main__":
    decripteaza_flag()
    ```

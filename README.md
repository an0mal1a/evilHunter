# evilHunter


Argumentos:
    
    OBLIGATORIO
        
        [♦] evilHunter [-w /path/to/wordlists] [-b 12 (passwd length)] [-t 400 (Nº of threads)]
        
            (-w / --wordlist)
                [♦] -w /path/to/wordlists

            (-b / --brute)
                [♦] -b passwd_length

            (-t / --threads)
                [♦] -t Nº_of_threads

            (-h / --help)
              
# INSTALACIÓN:

PyPi: (https://pypi.org/project/evilHunter/)

    command_line = pip install evilHunter

Git Hub:

    Command Lines:
    
        $ git clone https://github.com/an0mal1a/evilHunter
        $ cd evilHunter
        $ chmod 744 evilTrust
        $ sudo python3 setup.py install



# REQUERIMENTS:

    Esta herramienta requiere de python3 y de el pack
    de herramientas de 'aircrack-ng' y ' macchanger

        -   macchanger
        -   aircrack-ng
        -   airodump-ng
        -   aireplay-ng
        -   airmon-ng
    
# Install Tools
    ┌──(supervisor㉿kali-machine)-[~/ALL_MINE/CRACK_WIFI]
    └─$ sudo apt-get update -y && sudo apt-get install aircrack-ng -y && sudo apt-get install macchanger -y && sudo apt-get install wpasupplicant

               
# DICCIONARIO:
RockYou install -> (https://github.com/an0mal1a/evilHunter/releases/tag/RockYou)


# Procedimiento:

    1. Seleccionamos interfaz de red 'compatible' (wlan0) 
        y la establecemos en modo monitor.


    2. Escaneamos redes cercanas para guardar información sobre:

                · Cifrado
                · BSSID
                · Canal/Channel
                · ESSID/NOMBRE DE RED


    3. A la vez que estamos escaneando esa red fijando la tarjeta de
        red en el mismo canal, enviamos paquetes de deautenticación 
        

    4. Una véz capturado el handshake, abrimos el archivo .cap y
        con diccionary attack o generar contraseñas crackeamos la contraseña.

# _Proximas mejoras_

                [♦]  Brute Force (Password Generator) more Faster
                [♦]  Manual Capture handshake (No use extern tools)

For suggeriments or problems to fix --> https://github.com/an0mal1a/evilHunter/issues
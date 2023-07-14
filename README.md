# evilHunter

NOVEDADES:
        
        ¡Fuerza Brute en C!
        ¡Ahora puedes atacar a mas de 1 cliente!


Argumentos:
     
        
        [♦] evilHunter [-w /path/to/wordlists] [-b 12 (passwd length)] [-t 400 (Nº of threads)]
--- 
        [♦] Attack Type:

            (-w / --wordlist)
              -w /path/to/wordlists

            (-b / --brute)
              -b passwd_length ("r" for rand)
---
        [♦] Especification: 

            (-t / --threads)
                -t Nº_of_threads

            (-h / --help)
---
        [♦] Example:
                                                       ┌── (Path/to/wordlist)
            Wordlist attack --> sudo evilHunter.py -w /usr/share/wordlists/rockyou.txt

        -------------------------------------------------------------------------------
                                                              ┌──(500 threads)                                                              
            Dictionari attack --> sudo evilHunter.py -b r -t 500
                                                        └─(random length)

---



# INSTALACIÓN:

Git Hub: (v0.2a)
    
        FOR USE THE BRUTE FORCE 'C' INSTALL THE SETUP.PY FILE, 
             ¡DONT RUN IT DIRECTLY FROM THE DIR CLONED! 
        
     [!] ONE LINER: 
     
           git clone https://github.com/an0mal1a/evilHunter && chmod -R 744 evilHunter && cd evilHunter && sudo python3 setup.py install


     [!] COMMANDS

            1. git clone https://github.com/an0mal1a/evilHunter
            2. chmod -R 744 evilHunter
            3. cd evilHunter 
            5. sudo python3 setup.py install

    [*] END:

        ┌──(supervisor㉿kali-machine)-[~]
        └─$ evilHunter.py -h 
    
    

PyPi: (https://pypi.org/project/evilHunter/)   

    1.┌──(supervisor㉿kali-machine)-[~/Escritorio]
      └─$ pip install evilHunter
                
    2.┌──(supervisor㉿kali-machine)-[~/Escritorio]
      └─$ evilHunter.py 


# REQUERIMENTS:

    Esta herramienta requiere de python3 y de el pack
    de herramientas de 'aircrack-ng' y 'macchanger'

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

                · ESSID/NOMBRE DE RED
                · Cifrado
                · BSSID
                · Canal/Channel
                · Clientes
                · Power ( Señal )


    3. A la vez que estamos escaneando esa red fijando la tarjeta de
        red en el mismo canal, enviamos paquetes de deautenticación 
        

    4. Una véz capturado el handshake, abrimos el archivo .cap y
        con diccionary attack o generando contraseñas lo crackeamos.


For suggeriments or problems to fix --> https://github.com/an0mal1a/evilHunter/issues

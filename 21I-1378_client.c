#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>
#include "sha_256.h"
#include "AES_128_CBC.h"

#define PRIME 17    // Same prime number (p) as server
#define GENERATOR 3 // Same generator (g) as server

int sock;
int shared_key;

uint8_t iv[16] = {0x0f, 0x47, 0x0e, 0x7f, 0x75, 0x9c, 0x47, 0x0f, 0x42, 0xc6, 0xd3, 0x9c, 0xbc, 0x8e, 0x23, 0x25};

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

void create_socket() {
    sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8080);

    connect(sock, (struct sockaddr *) &server_address, sizeof(server_address));
}

int generate_private_key() {
    srand(time(NULL));
    return rand() % 10 + 1;  // Generate private key
}

int generate_public_key(int private_key) {
    return mod_exp(GENERATOR, private_key, PRIME); // Generate public key
}

void send_public_key(int public_key) {
    send(sock, &public_key, sizeof(public_key), 0); // Send public key to server
}

int receive_server_public_key() {
    int server_public_key;
    recv(sock, &server_public_key, sizeof(server_public_key), 0); // Receive server's public key
    return server_public_key;
}

int compute_shared_secret(int server_public_key, int private_key) {
    return mod_exp(server_public_key, private_key, PRIME); // Compute shared secret
}

void convert_to_aes_key(int shared_secret, uint8_t *aes_key) {
    for (int i = 0; i < 16; i++) {
        aes_key[i] = (shared_secret >> (8 * (15 - i))) & 0xFF; // Convert shared secret into 16 bytes
    }
}


void handle_communication() {
    char buf[256];

    while (1) {
        // Get user input and send it to the server
        printf("You (Client): ");
        char message[256];
        fgets(message, sizeof(message), stdin);

        // Remove newline character from the message
        message[strcspn(message, "\n")] = 0;

        // Send the message to the server
        send(sock, message, sizeof(message), 0);

        // If the client sends "exit", terminate the chat
        if (strcmp(message, "exit") == 0) {
            printf("You disconnected from the chat.\n");
            break;
        }

        // Clear buffer and receive response from server
        memset(buf, 0, sizeof(buf));
        int bytes_received = recv(sock, buf, sizeof(buf), 0);

        // If server sends "exit" or closes the connection (bytes_received == 0), client exits
        if (bytes_received <= 0 || strcmp(buf, "exit") == 0) {
            printf("Server disconnected. Exiting...\n");
            break;
        }

        printf("%s\n", buf);  // Display server's response
    }
}

void close_connection() {
    close(sock);  // Close the socket after communication
}


void ensure_multiple_of_16(char *data, size_t *length) {
    size_t mod_length = *length % 16;
    if (mod_length != 0) {
        // If length is not a multiple of 16, adjust it by truncating or adding zeros
        *length += (16 - mod_length); // Add padding (or truncate)
        data[*length] = '\0'; // Null terminate
    }
}

// Helper function to print the data in hexadecimal format
void print_hex(const unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}
// Function to handle signup
void signup() {
    char email[100], username[100], password[100];
    unsigned char signup_buffer[500]; // Buffer to hold all signup information
    unsigned char encrypted_buff[512]; // Buffer to hold encrypted data
    int bytes_received;
    char response[500]; // To hold server response
    
    // Example AES key derived from the shared secret or a fixed key
    uint8_t aes_key[16] = {0};  // 128-bit AES key (16 bytes)
    convert_to_aes_key(shared_key, aes_key);

    while (1) {
        // Get user input for signup information
        printf("\n--- Signup ---\n");
        printf("Enter Email: ");
        fgets(email, sizeof(email), stdin);
        email[strcspn(email, "\n")] = 0;  // Remove newline character

        printf("Enter Username: ");
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = 0;

        printf("Enter Password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0;

        // Format the signup buffer with all details
        snprintf((char *)signup_buffer, sizeof(signup_buffer), "Email: %s,Username: %s,Password: %s", email, username, password);
        
        size_t signup_length = strlen((char *)signup_buffer);
        

        // AES context initialization
        AES_CTX ctx;
        AES_EncryptInit(&ctx, aes_key, iv);
    
        // Ensure the plaintext length is a multiple of AES_BLOCK_SIZE (16 bytes)
        size_t padded_len = (signup_length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
        unsigned char padded_plaintext[padded_len];
        memset(padded_plaintext, 0, padded_len);
        memcpy(padded_plaintext, signup_buffer, signup_length);

        // Encryption: Process in blocks
        unsigned char encrypted_data[padded_len];
        unsigned char encrypted_block[AES_BLOCK_SIZE];
        for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
            AES_Encrypt(&ctx, padded_plaintext + i, encrypted_block);
            memcpy(encrypted_data + i, encrypted_block, AES_BLOCK_SIZE);
        }

        // Display encrypted data
        printf("Encrypted Data: ");
        print_hex(encrypted_data, padded_len);
        
        // Send the encrypted data to the server (correct data)
        send(sock, encrypted_data, padded_len, 0);

        // Receive server response
        bytes_received = recv(sock, response, sizeof(response), 0);
        if (bytes_received > 0) {
            response[bytes_received] = '\0';  // Null-terminate the received string
            printf("Server Response: %s\n", response);  // Print server's response

            // Check if signup was successful
            if (strstr(response, "Signup successful") != NULL) {
                // Signup successful, exit the loop
                printf("Signup successful!\n");
                break;  // Exit the loop after successful signup
            } else {
                // Signup failed, ask the user to re-enter credentials
                printf("Signup failed. Please try again.\n");
            }
        } else {
            printf("Error receiving response from server.\n");
            break;  // Exit the loop if there is an error receiving the response
        }
    }
}


void login() {
    char username[100], password[100];
    unsigned char login_buffer[500]; // Buffer to hold all login information
    unsigned char encrypted_data[512]; // Buffer to hold encrypted data
    int bytes_received;
    char response[500]; // To hold server response
    
    // Example AES key derived from the shared secret or a fixed key
    uint8_t aes_key[16] = {0};  // 128-bit AES key (16 bytes)
    convert_to_aes_key(shared_key, aes_key);

    while (1) {
        // Get user input for login
        printf("\n--- Login ---\n");

        // Collecting username
        printf("Enter Username: ");
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = 0;  // Remove newline character

        // Collecting password
        printf("Enter Password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0;

        // Format the login buffer with username and password
        snprintf((char *)login_buffer, sizeof(login_buffer), "Username: %s,Password: %s", username, password);

        size_t login_length = strlen((char *)login_buffer);

        // AES context initialization
        AES_CTX ctx;
        AES_EncryptInit(&ctx, aes_key, iv);

        // Ensure the plaintext length is a multiple of AES_BLOCK_SIZE (16 bytes)
        size_t padded_len = (login_length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
        unsigned char padded_plaintext[padded_len];
        memset(padded_plaintext, 0, padded_len);
        memcpy(padded_plaintext, login_buffer, login_length);

        // Encryption: Process in blocks
        unsigned char encrypted_block[AES_BLOCK_SIZE];
        for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
            AES_Encrypt(&ctx, padded_plaintext + i, encrypted_block);
            memcpy(encrypted_data + i, encrypted_block, AES_BLOCK_SIZE);
        }

        // Display encrypted data
        printf("Encrypted Data: ");
        print_hex(encrypted_data, padded_len);
        
        // Send the encrypted data to the server
        send(sock, encrypted_data, padded_len, 0);

        // Receive the server's response for login status
        bytes_received = recv(sock, response, sizeof(response), 0);
        if (bytes_received > 0) {
            response[bytes_received] = '\0';  // Null-terminate the received string
            printf("Server Response: %s\n", response);  // Print server's response

            // Check if login was successful
            if (strstr(response, "Login successful") != NULL) {
                // Login successful, exit the loop
                printf("Login successful! Welcome, %s.\n", username);
                break;  // Exit the loop after successful login
            } else {
                // Login failed, ask the user to re-enter credentials
                printf("Login failed. Please try again.\n");
            }
        } else {
            printf("Error receiving response from server.\n");
            break;  // Exit the loop if there is an error receiving the response
        }
    }
}




// Function to display the menu and return the chosen option
void display_menu() {
    int choice;
    printf("\n\t*** Welcome to the Chat Application ***\n");
    printf("1. Signup\n");
    printf("2. Login\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);
    getchar(); // Clear newline character from input buffer
    switch (choice)
    {
    case 1:
        signup();
        break;
    case 2:
        login();
        break;
    default:
        printf("\nNot a valid option.\n");
        break;
    }
}


int main() {
    printf("\n\t>>>>>>>>>> Fast University Chat Client <<<<<<<<<<\n\n");

    // Create socket and connect to the server
    create_socket();

    // Generate the client's private key and public key
    int private_key = generate_private_key();  // Client's private key
    int public_key = generate_public_key(private_key); // Client's public key

    // Receive the server's public key
    int server_public_key = receive_server_public_key();

    // Send the client's public key to the server
    send_public_key(public_key);

    // Compute the shared secret
    shared_key = compute_shared_secret(server_public_key, private_key); // Compute shared key
    printf("Client's shared secret: %d\n", shared_key);

    display_menu();

    // Handle communication with the server
    handle_communication();

    // Close the connection
    close_connection();

    return 0;
}

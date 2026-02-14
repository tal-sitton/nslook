#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"


int main(const int argc, const char **argv) {
    if (argc < NEEDED_ARGS_COUNT || argc > MAX_ARGS_COUNT) {
        printf(
            "nslook <input_file> <output_file> [OPTIONAL: NAMESERVER. default is %s] [OPTIONAL - to use ipv6: AAA. default is A]\n",
            DEFAULT_NAMESERVER);
        return 1;
    }

    const char *input_filename = argv[INPUT_FILE_ARG_INDEX];
    const char *output_filename = argv[OUTPUT_FILE_ARG_INDEX];
    const char *nameserver = argc >= NAMESERVER_ARG_INDEX + 1 ? argv[NAMESERVER_ARG_INDEX] : DEFAULT_NAMESERVER;
    const uint8_t record_type = argc >= RECORD_TYPE_ARG_INDEX + 1
                                    ? strcmp(argv[RECORD_TYPE_ARG_INDEX], "AAAA") == 0
                                          ? RECORD_TYPE_AAAA
                                          : RECORD_TYPE_A
                                    : RECORD_TYPE_A;

    const struct DomainsInfo domains_info = get_domains_from_file(input_filename);
    if (domains_info.domains == NULL) {
        fprintf(stderr, "Could not read file %s!\n", input_filename);
        return 1;
    }
    if (domains_info.count == 0) {
        fprintf(stderr, "The input file %s is empty!\n", input_filename);
        free_domains(domains_info);
        return 1;
    }

    struct ResolvedAddress resolved[domains_info.count] = {};
    const int socket_fd = connect_socket(nameserver);

    if (socket_fd == -1) {
        return 1;
    }

    bool resolve_success = false;
    for (size_t i = 0; i < SOCKET_TIMEOUT_RETRIES && !resolve_success; i++) {
        resolve_success = resolve_domains(domains_info.domains, socket_fd, resolved, domains_info.count,
                                          record_type);
        if (!resolve_success) {
            printf("ERROR while resolving domains. trying again (%d/%d)\n", i+1, SOCKET_TIMEOUT_RETRIES);
        }
    }
    close(socket_fd);

    if (!resolve_success) {
        perror("Couldnt resolve domains");
        free_domains(domains_info);
        return 1;
    }

    const bool success = output_to_file(resolved, output_filename, domains_info.count, record_type);
    free_domains(domains_info);
    free_resolved(resolved, domains_info.count);
    if (!success) {
        fprintf(stderr, "Could not write to file %s!\n", output_filename);
        return 1;
    }
    return 0;
}

struct DomainsInfo get_domains_from_file(const char *filename) {
    FILE *file_ptr = fopen(filename, "r");
    if (file_ptr == NULL) {
        return (struct DomainsInfo){NULL, 0};
    }

    char **domains = malloc(sizeof(char *));
    domains[0] = malloc(MAX_DOMAIN_CHARS);
    size_t i = 0;
    for (; fgets(domains[i], MAX_DOMAIN_CHARS, file_ptr); i++) {
        if (domains[i][strlen(domains[i]) - 1] == '\n') {
            domains[i][strlen(domains[i]) - 1] = '\0';
        } else {
            domains[i][strlen(domains[i])] = '\0';
        }
        domains[i] = realloc(domains[i], strlen(domains[i]) + 1);
        domains = realloc(domains, (i + 2) * sizeof(char *));
        domains[i + 1] = malloc(MAX_DOMAIN_CHARS);
    }
    free(domains[i]);
    fclose(file_ptr);
    return (struct DomainsInfo){domains, i};
}

void free_domains(const struct DomainsInfo addresses) {
    for (int i = 0; i < addresses.count; i++) {
        free(addresses.domains[i]);
    }
    free(addresses.domains);
}

void free_resolved(const struct ResolvedAddress *resolved, const size_t resolved_count) {
    for (size_t i = 0; i < resolved_count; i++) {
        free(resolved[i].ip);
    }
}

void deserialize_ip(uint8_t const *raw_ip, const uint16_t record_type, char *result) {
    if (record_type == RECORD_TYPE_A) {
        struct in_addr ip_addr;
        ip_addr.s_addr = *(uint32_t *) raw_ip;
        memcpy(result, inet_ntoa(ip_addr), strlen(inet_ntoa(ip_addr)));
    }
    if (record_type == RECORD_TYPE_AAAA) {
        for (int i = 0; i < 16; i += 2) {
            sprintf(result + (i / 2) * 5, "%02x%02x:", raw_ip[i], raw_ip[i + 1]);
        }
        result[FORMATTED_IPV6_LENGTH - 1] = 0;
    }
}

bool output_to_file(const struct ResolvedAddress *resolved, const char *filename, const size_t resolved_count,
                    const uint16_t record_type) {
    FILE *fptr = fopen(filename, "w");
    if (fptr == NULL) {
        return false;
    }

    for (int i = 0; i < resolved_count; i++) {
        if (*resolved[i].ip == 0) {
            fprintf(fptr, "%s -> ERROR\n", resolved[i].domain);
        } else {
            char ip_addr[FORMATTED_IPV6_LENGTH] = {};
            deserialize_ip(resolved[i].ip, record_type, ip_addr);
            fprintf(fptr, "%s -> %s\n", resolved[i].domain, ip_addr);
        }
    }
    fclose(fptr);
    return true;
}

int connect_socket(const char *nameserver) {
    struct sockaddr_in server_address;
    bzero(&server_address, sizeof(server_address));
    server_address.sin_addr.s_addr = inet_addr(nameserver);
    server_address.sin_port = htons(DNS_PORT);
    server_address.sin_family = AF_INET;
    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT_SECONDS;
    timeout.tv_usec = 0;

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof timeout) < 0)
        perror("setsockopt failed\n");


    if (connect(socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        perror("Failed to connect");
        return -1;
    }
    return socket_fd;
}

void serialize_domain(const char *domain, char *formatted_domain) {
    int chars_counter = -1; //because of the null byte
    for (int i = strlen(domain); i >= 0; i--) {
        if (domain[i] == '.') {
            formatted_domain[i + 1] = (char) chars_counter;
            chars_counter = 0;
        } else {
            formatted_domain[i + 1] = domain[i];
            chars_counter++;
        }
    }
    formatted_domain[0] = (char) chars_counter;
}

void create_request_body(const char *domain, char *body, const uint16_t record_type) {
    strcpy(body, domain);
    body[strlen(domain) + 1] = 0;
    const struct DnsQueryInfo query_info = {htons(record_type), htons(CLASS_CODE)};
    memcpy(body + 1 + (strlen(domain) * sizeof(char)), &query_info, sizeof(query_info));
}

struct DnsPacketInfo generate_dns_query(const char *domain, const uint16_t record_type) {
    char formatted_domain[strlen(domain)] = {};
    serialize_domain(domain, formatted_domain);

    const size_t request_body_length = strlen(formatted_domain) + 1 + sizeof(struct DnsQueryInfo);
    char request_body[request_body_length] = {};
    create_request_body(formatted_domain, request_body, record_type);

    const size_t packet_length = sizeof(struct DnsHeader) + request_body_length;
    struct DnsPacket *p = malloc(packet_length);
    p->header = (struct DnsHeader){htons(TRANSACTION_ID), htons(DNS_FLAGS), htons(1), 0, 0, 0};
    memcpy(p->data, request_body, request_body_length);
    return (struct DnsPacketInfo){packet_length, p};
}

void deserialize_domain(char const *raw_domain, char *domain) {
    size_t offset = 0;
    size_t batch_size = (size_t) raw_domain[0];
    while (batch_size != 0) {
        for (int i = 0; i < batch_size; i++) {
            domain[offset + i] = raw_domain[offset + i + 1];
        }
        domain[offset + batch_size] = '.';
        offset += batch_size + 1;
        batch_size = (size_t) raw_domain[offset];
    }
    domain[offset + batch_size - 1] = 0;
}

void unpack_dns_packet(const char *result, struct DnsPacket *dns_packet, const size_t request_size) {
    memcpy(dns_packet, result, request_size);
    dns_packet->header.transaction_id = ntohs(dns_packet->header.transaction_id);
    dns_packet->header.flags = ntohs(dns_packet->header.flags);
    dns_packet->header.question_count = ntohs(dns_packet->header.question_count);
    dns_packet->header.answer_count = ntohs(dns_packet->header.answer_count);
    dns_packet->header.authority_count = ntohs(dns_packet->header.authority_count);
    dns_packet->header.additional_count = ntohs(dns_packet->header.additional_count);
}

void unpack_query_info(struct DnsPacket const *dns_packet, struct DnsQueryInfo *queryInfo, size_t offset) {
    memcpy(queryInfo, dns_packet->data + offset, sizeof(struct DnsQueryInfo));
    queryInfo->type = ntohs(queryInfo->type);
    queryInfo->class = ntohs(queryInfo->class);
}

void unpack_response_fields(struct DnsPacket const *dns_packet, struct DnsResponseFields *dns_response_fields,
                            const size_t offset) {
    memcpy(dns_response_fields, dns_packet->data + offset, sizeof(struct DnsResponseFields));
    dns_response_fields->ttl = ntohl(dns_response_fields->ttl);
    dns_response_fields->data_length = ntohs(dns_response_fields->data_length);
}

bool extract_valid_response_from_answers(struct DnsPacket const *dns_packet, struct DnsQueryInfo const *queryInfo,
                                         size_t offset,
                                         uint8_t *result) {
    for (size_t i = 0; i < dns_packet->header.answer_count; i++) {
        struct DnsQueryInfo *answerInfo = malloc(sizeof(struct DnsQueryInfo));
        unpack_query_info(dns_packet, answerInfo, offset);

        offset += sizeof(struct DnsQueryInfo);

        struct DnsResponseFields *dns_response_fields = malloc(sizeof(struct DnsResponseFields));
        unpack_response_fields(dns_packet, dns_response_fields, offset);

        offset += sizeof(struct DnsResponseFields);

        char raw_result[dns_response_fields->data_length];

        memcpy(raw_result, dns_packet->data + offset, dns_response_fields->data_length);


        if (answerInfo->type != queryInfo->type) {
            printf("Found info, but its type is %d and you searched for %d. Found: %s\n",
                   answerInfo->type, queryInfo->type, raw_result);
        } else {
            memcpy(result, raw_result, dns_response_fields->data_length);
            free(answerInfo);
            free(dns_response_fields);
            return true;
        }

        offset += dns_response_fields->data_length + 2;
        free(answerInfo);
        free(dns_response_fields);
    }
    return false;
}

bool parse_dns_result(const char *response, const size_t request_size, const uint16_t record_type, uint8_t *result,
                      const size_t result_size) {
    struct DnsPacket *dns_packet = malloc(request_size);
    unpack_dns_packet(response, dns_packet, request_size);

    if (dns_packet->header.answer_count < dns_packet->header.question_count) {
        fprintf(stderr, "There are more questions then answers\n");
        memset(result, 0, result_size);
        free(dns_packet);
        return false;
    }

    char parsed_domain[strlen(dns_packet->data)] = {};
    deserialize_domain(dns_packet->data, parsed_domain);

    struct DnsQueryInfo *queryInfo = malloc(sizeof(struct DnsQueryInfo));
    unpack_query_info(dns_packet, queryInfo, sizeof(parsed_domain) + sizeof(char));

    const size_t offset = sizeof(parsed_domain) + sizeof(char) + sizeof(struct DnsQueryInfo) + 2;
    const bool found_answer = extract_valid_response_from_answers(dns_packet, queryInfo, offset, result);

    free(dns_packet);
    free(queryInfo);

    if (!found_answer) {
        fprintf(stderr, "couldnt find matching result for %s\n", parsed_domain);
        return false;
    }
    char ip_addr[FORMATTED_IPV6_LENGTH] = {};
    deserialize_ip(result, record_type, ip_addr);
    printf("Found: %s -> %s\n", parsed_domain, ip_addr);
    return true;
}

bool resolve_domains(char **domains, const int socket_fd, struct ResolvedAddress *resolved,
                     const size_t domain_count, const uint16_t record_type) {
    for (size_t i = 0; i < domain_count; i++) {
        const struct DnsPacketInfo dns_packet_info = generate_dns_query(domains[i], record_type);
        const ssize_t send_status = sendto(socket_fd, dns_packet_info.packet, dns_packet_info.size, 0, NULL,
                                           sizeof(struct sockaddr_in));
        if (send_status == -1) {
            perror("Couldnt send request");
            return false;
        }
        free(dns_packet_info.packet);

        char response[1024] = {};

        const ssize_t recv_status = recvfrom(socket_fd, response, sizeof(response), 0, NULL, NULL);
        if (recv_status == -1) {
            perror("Couldnt receive response");
            return false;
        }
        const size_t ip_size = record_type == RECORD_TYPE_A ? 4 : 16;
        uint8_t *ip = malloc(ip_size);

        const bool parse_success = parse_dns_result(response, sizeof(response), record_type, ip, ip_size);

        if (parse_success == false) {
            fprintf(stderr, "error while parsing dns result for %s\n", domains[i]);
        }

        resolved[i] = (struct ResolvedAddress){ip, domains[i]};
    }
    return true;
}

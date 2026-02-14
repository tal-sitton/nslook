#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// DNS Consts
static const uint8_t MAX_DOMAIN_CHARS = 254 * sizeof(char);
static const uint8_t RECORD_TYPE_A = 1;
static const uint8_t RECORD_TYPE_AAAA = 28;
static const uint8_t CLASS_CODE = 1;
static const uint16_t TRANSACTION_ID = 0x0555;
static const uint16_t DNS_FLAGS = 0x100;
static const uint8_t DNS_PORT = 53;
static const uint8_t FORMATTED_IPV6_LENGTH = 32 + 8; //including `:`
// Program Consts
static const char *DEFAULT_NAMESERVER = "1.1.1.1";
static const uint8_t SOCKET_TIMEOUT_SECONDS = 4;
static const uint8_t SOCKET_TIMEOUT_RETRIES = 4;

static const int NEEDED_ARGS_COUNT = 3;
static const int MAX_ARGS_COUNT = 5;
static const int INPUT_FILE_ARG_INDEX = 1;
static const int OUTPUT_FILE_ARG_INDEX = 2;
static const int NAMESERVER_ARG_INDEX = 3;
static const int RECORD_TYPE_ARG_INDEX = 4;

#pragma pack(push, 1)
struct ResolvedAddress {
    uint8_t *ip;
    char *domain;
};

struct DomainsInfo {
    char **domains;
    size_t count;
};

struct DnsQueryInfo {
    uint16_t type;
    uint16_t class;
};

struct DnsResponseFields {
    uint32_t ttl;
    uint16_t data_length;
};

struct DnsHeader {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
};


struct DnsPacket {
    struct DnsHeader header;
    char data[];
};

struct DnsPacketInfo {
    size_t size;
    struct DnsPacket *packet;
};
#pragma pack(pop)


struct DomainsInfo get_domains_from_file(const char *filename);

void free_domains(struct DomainsInfo addresses);

void free_resolved(const struct ResolvedAddress *resolved, size_t resolved_count);

void deserialize_ip(const uint8_t *raw_ip, uint16_t record_type, char *result);

bool output_to_file(const struct ResolvedAddress *resolved, const char *filename, size_t resolved_count,
                    uint16_t record_type);

int connect_socket(const char *nameserver);

void serialize_domain(const char *domain, char *formatted_domain);

void create_request_body(const char *domain, char *body, uint16_t record_type);

struct DnsPacketInfo generate_dns_query(const char *domain, uint16_t record_type);

void deserialize_domain(char const *raw_domain, char *domain);

void unpack_dns_packet(const char *result, struct DnsPacket *dns_packet, size_t request_size);

void unpack_query_info(struct DnsPacket const *dns_packet, struct DnsQueryInfo *queryInfo, size_t offset);

void unpack_response_fields(struct DnsPacket const *dns_packet, struct DnsResponseFields *dns_response_fields,
                            size_t offset);

bool extract_valid_response_from_answers(struct DnsPacket const *dns_packet,
                              struct DnsQueryInfo const *queryInfo, size_t offset,
                              uint8_t *result);

bool parse_dns_result(const char *response, size_t request_size, uint16_t record_type, uint8_t *result,
                      size_t result_size);

bool resolve_domains(char **domains, int socket_fd, struct ResolvedAddress *resolved, size_t domain_count,
                     uint16_t record_type);

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include "LDAPMessage.h"

static LDAPMessage_t *receive_ldap_message();
static LDAPMessage_t *bind_response_ok(int messageId, LDAPDN_t *dn);
static LDAPMessage_t *search_result_entry(int messageId, char *name, char *email, char *jpegFilename);
static LDAPMessage_t *search_result_done(int messageId, LDAPDN_t *dn);
static void send_ldap_message(int fd, LDAPMessage_t *msg);
static int accept_single_connection(int port);

int main() {
    LDAPMessage_t *req_bind, *req_search, *req_unbind;
    LDAPMessage_t *rsp_bind, *rsp_search1, *rsp_search2, *rsp_search_done;

    int sock = accept_single_connection(3389);

    fprintf(stderr, "Receiving LDAP message...\n");
    req_bind = receive_ldap_message(sock);
    assert(req_bind);
    assert(req_bind->protocolOp.present == LDAPMessage__protocolOp_PR_bindRequest);
    assert(req_bind->protocolOp.choice.bindRequest.version == 3);
    fprintf(stderr, "Received BindRequest...\n");
    asn_fprint(stderr, &asn_DEF_LDAPMessage, req_bind);

    fprintf(stderr, "Sending BindReply...\n");
    rsp_bind = bind_response_ok(req_bind->messageID, &req_bind->protocolOp.choice.bindRequest.name);
    asn_fprint(stderr, &asn_DEF_LDAPMessage, rsp_bind);
    send_ldap_message(sock, rsp_bind);

    req_search = receive_ldap_message(sock);
    assert(req_search->protocolOp.present == LDAPMessage__protocolOp_PR_searchRequest);
    fprintf(stderr, "Received SearchRequest...\n");
    xer_fprint(stderr, &asn_DEF_LDAPMessage, req_search);

    rsp_search1 = search_result_entry(req_search->messageID, "Lev Walkin", "vlm@fprog.ru", "avatar.jpg");
    asn_fprint(stderr, &asn_DEF_LDAPMessage, rsp_search1);
    send_ldap_message(sock, rsp_search1);

    rsp_search2 = search_result_entry(req_search->messageID, "Olga Bobrova", "oley@fprog.ru", NULL);
    asn_fprint(stderr, &asn_DEF_LDAPMessage, rsp_search2);
    send_ldap_message(sock, rsp_search2);

    rsp_search_done = search_result_done(req_search->messageID, &req_search->protocolOp.choice.searchRequest.baseObject);
    asn_fprint(stderr, &asn_DEF_LDAPMessage, rsp_search_done);
    send_ldap_message(sock, rsp_search_done);

    req_unbind = receive_ldap_message(sock);
    assert(req_unbind->protocolOp.present == LDAPMessage__protocolOp_PR_unbindRequest);
    xer_fprint(stderr, &asn_DEF_LDAPMessage, req_unbind);

    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, req_bind);
    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, req_search);
    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, req_unbind);
    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, rsp_bind);
    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, rsp_search1);
    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, rsp_search2);
    ASN_STRUCT_FREE(asn_DEF_LDAPMessage, rsp_search_done);

    return 0;
}

static int accept_single_connection(int port) {
    struct sockaddr_in sin;
    int err;
    int lsock, sock;
    int opt_true = ~0;

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(3389);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    lsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(lsock, SOL_SOCKET, SO_REUSEPORT, &opt_true, sizeof(opt_true));
    err = bind(lsock, (struct sockaddr *)&sin, sizeof sin);
    assert(err == 0);
    err = listen(lsock, 1);
    assert(err == 0);

    sock = accept(lsock, 0, 0);
    assert(sock > 0);
    close(lsock);

    return sock;
}

static LDAPMessage_t *bind_response_ok(int messageId, LDAPDN_t *dn) {
    LDAPMessage_t *msg = calloc(1, sizeof *msg);
    BindResponse_t *resp;

    msg->messageID = messageId;
    msg->protocolOp.present = LDAPMessage__protocolOp_PR_bindResponse;
    resp = &msg->protocolOp.choice.bindResponse;
    asn_long2INTEGER(&resp->resultCode, BindResponse__resultCode_success);
    OCTET_STRING_fromBuf(&resp->matchedDN, dn->buf, dn->size);
    OCTET_STRING_fromString(&resp->diagnosticMessage, "OK");

    return msg;
}

static PartialAttribute_t *make_partial_attribute(char *key, char *value) {
    PartialAttribute_t *pa = calloc(1, sizeof *pa);

    OCTET_STRING_fromString(&pa->type, key);
    ASN_SEQUENCE_ADD(&pa->vals,
        OCTET_STRING_new_fromBuf(&asn_DEF_AttributeValue, value, -1));

    return pa;
}

static PartialAttribute_t *make_partial_attribute_from_file(char *key, char *filename) {
    PartialAttribute_t *pa = calloc(1, sizeof *pa);
    char buffer[4096];
    size_t buflen;

    FILE *f = fopen(filename, "rb");
    assert(f);
    buflen = fread(buffer, 1, sizeof buffer, f);
    fclose(f);

    OCTET_STRING_fromString(&pa->type, key);
    ASN_SEQUENCE_ADD(&pa->vals,
        OCTET_STRING_new_fromBuf(&asn_DEF_AttributeValue, buffer, buflen));

    return pa;
}

static LDAPMessage_t *search_result_entry(int messageId, char *name, char *email, char *jpegFilename) {
    LDAPMessage_t *msg = calloc(1, sizeof *msg);
    SearchResultEntry_t *entry;

    msg->messageID = messageId;
    msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResEntry;
    entry = &msg->protocolOp.choice.searchResEntry;
    OCTET_STRING_fromString(&entry->objectName, name);

    ASN_SEQUENCE_ADD(&entry->attributes, make_partial_attribute("cn", name));
    ASN_SEQUENCE_ADD(&entry->attributes, make_partial_attribute("mail", email));
    if(jpegFilename)
        ASN_SEQUENCE_ADD(&entry->attributes,
            make_partial_attribute_from_file("jpegPhoto", jpegFilename));

    return msg;
}

static LDAPMessage_t *search_result_done(int messageId, LDAPDN_t *dn) {
    LDAPMessage_t *msg = calloc(1, sizeof *msg);
    SearchResultDone_t *done;

    msg->messageID = messageId;
    msg->protocolOp.present = LDAPMessage__protocolOp_PR_searchResDone;
    done = &msg->protocolOp.choice.searchResDone;
    asn_long2INTEGER(&done->resultCode, LDAPResult__resultCode_success);
    OCTET_STRING_fromBuf(&done->matchedDN, dn->buf, dn->size);
    OCTET_STRING_fromString(&done->diagnosticMessage, "OK");
    return msg;
}

static int output_cb(const void *buffer, size_t size, void *key) {
    return write(*(int *)key, buffer, size);
}

static void send_ldap_message(int fd, LDAPMessage_t *msg) {
    der_encode(&asn_DEF_LDAPMessage, msg, output_cb, &fd);
}

static LDAPMessage_t *receive_ldap_message(int fd) {
    char buffer[8192];
    ssize_t buffer_len = 0;
    LDAPMessage_t *msg = 0;
    asn_dec_rval_t rv;

    buffer_len = read(fd, buffer, sizeof(buffer));
    if(buffer_len <= 0)
        return NULL;

    rv = ber_decode(0, &asn_DEF_LDAPMessage, (void **)&msg, buffer, buffer_len);
    if(rv.code != RC_OK)
        return NULL;

    assert(rv.consumed == buffer_len);

    return msg;
}

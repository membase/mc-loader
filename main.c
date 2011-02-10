#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <libmemcached/memcached.h>

typedef enum {
  MCLOADER_SUCCESS = 0,
  MCLOADER_MCFAIL  = 1,
  MCLOADER_SIZEDIF = 2,
  MCLOADER_DATADIF = 3,
} MCLOADER_ERROR_CODE;

typedef struct {
  char* key;
  size_t nkey;
  char* data;
  size_t size;
} KV;

typedef struct {
  char* hostname;
  int port;
  char* sasl_username;
  char* sasl_password;
} Credentials;

bool doSet(memcached_st* memc, KV* kv, int oom_error_code);
bool doGet(memcached_st* memc, KV* kv, uint32_t *flags);
memcached_st* memcacheConnect(Credentials* credentials, bool binary);
KV* getNextKV(FILE* file, char* fixed_data);
void usage(void);

int main(int argc, char **argv) {
  memcached_st* memc;
  KV* kv;
  Credentials* credentials = (Credentials*) malloc(sizeof(Credentials));
  bool check = false;
  bool binary = false;
  uint32_t flags;
  FILE *file;
  char *fixed_data = NULL;
  int fails = 0;
  int passes = 0;
  int oom_error_code = 10;
  int threads = 1;
  int i;

  while (1) {
    static struct option long_options[] = {
      {"binary", no_argument, 0, 'b'},
      {"check", no_argument, 0, 'c'},
      {"help", no_argument, 0, 'i'},
      {"hostname", required_argument, 0, 'h'},
      {"keyset", required_argument, 0, 'k'},
      {"password", required_argument, 0, 'P'},
      {"port", required_argument, 0, 'p'},
      {"threads", required_argument, 0, 't'},
      {"username", required_argument, 0, 'u'},
      {"valuesize", required_argument, 0, 'v'}
    };
    int c;
    int option_index = 0;
    c = getopt_long(argc, argv, "bch:k:p:P:t:u:s:", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'b':
      binary = true;
      break;
    case 'c':
      check = true;
      break;
    case 'h':
      credentials->hostname = optarg;
      if (credentials->port == 0)
	credentials->port = 11211;
      break;
    case 'i':
      usage();
      exit(0);
    case 'k':
      if (strcmp(optarg,"-") == 0) {
	file = stdin;
      } else {
	file = fopen(optarg, "r");
      }
      break;
    case 'P':
      credentials->sasl_password = optarg;
      break;
    case 'p':
      credentials->port = atoi(optarg);
      break;
    case 's':
      fixed_data = malloc(atoi(optarg)+1);
      for (i = 0; i < atoi(optarg); i++) {
	fixed_data[i]='a';
      }
      fixed_data[atoi(optarg)] = 0;
      break;
    case 't':
      threads = atoi(optarg);
      break;
    case 'u':
      credentials->sasl_username = optarg;
      if (credentials->sasl_password == NULL)
	credentials->sasl_password = strdup("");
      binary = true;
      break;
    case '?':
      break;
    default:
      abort();
    } 
  }

  if (credentials->hostname == NULL) {
    fprintf(stderr, "Hostname required\n");
    usage();
    exit(1);
  }
  if (file == NULL) {
    fprintf(stderr, "Failed to open keyset\n");
    usage();
    exit(1);
  }

  memc = memcacheConnect(credentials, binary);

  while( (kv = getNextKV(file, fixed_data)) != NULL) {
    if (check == false) {
      if (doSet(memc, kv, oom_error_code)) {
	passes++;
      } else {
	fails++;
      }
    } else {
      if (doGet(memc, kv, &flags)) {
	passes++;
      } else {
	fails++;
      }
    }
    free(kv);
  }
  if (credentials->sasl_username != NULL && credentials->sasl_password != NULL) {
    memcached_destroy_sasl_auth_data(memc);
  }
  printf("pass: %d\n",passes);
  printf("fail: %d\n",fails);

  if (fails > 0)
    return 1;
  return 0;
}

memcached_st* memcacheConnect(Credentials* credentials, bool binary) {
  memcached_st* memc = memcached_create(NULL);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 1);
  if (binary) {
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
  }
  if (credentials->sasl_username != NULL && credentials->sasl_password != NULL) {
    if (sasl_client_init(NULL) != SASL_OK) {
      fprintf(stderr, "Failed to initialize sasl library!\n");
      exit(1);
    }
    memc->sasl = malloc(sizeof(struct memcached_sasl_st));
    memc->sasl->callbacks = NULL;
    memc->sasl->is_allocated = false;
    memcached_set_sasl_auth_data(memc, credentials->sasl_username, credentials->sasl_password);
  }
  memcached_server_add(memc, credentials->hostname, credentials->port);
  return memc;
}

KV* getNextKV(FILE* file, char* fixed_data) {
  char *buffer = malloc(sizeof(char) * 64);
  char *ptr = NULL;
  KV* kv = (KV*) malloc(sizeof(KV));

  if (fgets(buffer,63,file) != NULL) {
    kv->key = strdup(buffer);
    ptr = strchr(kv->key, ' ');
    if (ptr == NULL) {
      return NULL;
    }
    *ptr = '\0';
    kv->data = ptr + 1;
    ptr = strchr(kv->data, '\n');
    if (ptr != NULL) {
      *ptr = '\0';
    }
    if (fixed_data != NULL) {
      kv->data = fixed_data;
    }
    kv->nkey = strlen(kv->key);
    kv->size = strlen(kv->data);
    return kv;
  } else {
    return NULL;
  }
}

bool doGet(memcached_st* memc, KV* kv, uint32_t *flags) {
  memcached_return_t rc;
  size_t rsize = 0;
  bool pass = false;
  int err_reason = MCLOADER_SUCCESS;

  char* rdata = memcached_get(memc, kv->key, kv->nkey, &rsize, flags, &rc);
  err_reason = MCLOADER_SUCCESS;
  pass = true;
  if (rc != MEMCACHED_SUCCESS) {
    pass = false;
    err_reason = MCLOADER_MCFAIL;
  } else if (rsize != kv->size) {
    pass = false;
    err_reason = MCLOADER_SIZEDIF;
  } else if (memcmp(kv->data, rdata, kv->size) != 0) {
    pass = false;
    err_reason = MCLOADER_DATADIF;
  }
  if (pass == false) {
    switch (err_reason) {
    case MCLOADER_MCFAIL:
      fprintf(stderr, "Failed to get: %s, memcached failure %d\n", kv->key, rc);
      break;
    case MCLOADER_SIZEDIF:
      fprintf(stderr, "Failed to get: %s, data size difference. expected %lu, got %lu\n", kv->key, kv->size, rsize);
      break;
    case MCLOADER_DATADIF:
      fprintf(stderr, "Failed to get: %s, data value difference\n", kv->key);
      break;
    default:
      fprintf(stderr, "Failed to get: %s, mcloader failure %d\n", kv->key, err_reason);
    }
  }
  free(rdata);
  return pass;
}

bool doSet(memcached_st* memc, KV* kv, int oom_error_code) {
  memcached_return_t rc;
  bool pass;
  int backoff_us = 0;
  // if we fail to set, backoff then try again up to a 10 second backoff
  do {
    rc = memcached_set(memc, kv->key, kv->nkey, kv->data, kv->size, 0, 0);
    // only backoff on temp mem errors
    if (rc == oom_error_code) {
      backoff_us += 10000 + (backoff_us/20);
      if (backoff_us > 4000000) {
	backoff_us = 4000000;
      }
#ifdef VERBOSE
      fprintf(stderr, "backing off %s, %d us due to error: %d\n", kv->key, backoff_us, rc);
#endif
      usleep(backoff_us);
    }
  }
  while ((rc == oom_error_code) && (backoff_us < 4000000));
  if (rc != MEMCACHED_SUCCESS) {
    pass = false;
    fprintf(stderr, "Failed to set: %s, due to error: %d\n", kv->key, rc);
  } else {
    pass = true;
  }
  backoff_us -= (10000 + (backoff_us/20));
  if (backoff_us < 0) {
    backoff_us = 0;
  }
#ifdef VERBOSE
  if (backoff_us > 0) {
    fprintf(stderr, "backoff: %d us\n", backoff_us);
  }
#endif
  return pass;
}

void usage(void) {
  printf("-b,--binary\tSpecifies use of the binary protocol\n");
  printf("-c,--check\tChecks key-value pairs in the host sever with key-value pairs in\n");
  printf("\t\tthe specified keyset. If not specifed key-value pairs will be loaded\n");
  printf("\t\tfrom the keyset into the host serer\n");
  printf("-i,--help\tPrints help information\n");
  printf("-h,--hostname\t(Required) Specifies the host to connect to\n");
  printf("-k,--keyset\t(Required) Specifies a file containing keys\n");
  printf("-P,--password\tSpecifies the password (only for sasl authentication\n");
  printf("-p,--port\tThe port to use, default is 11211\n");
  printf("-s,--valuesize\tThe size of the value for each key\n");
  printf("-t,--threads\tThe number of threads to use\n");
  printf("-u,--username\tSpecifies the username (only for SASL authentication)\n");
}

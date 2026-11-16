// SPDX-License-Identifier: MIT
// reseed.node: lets the JavaScript runtime adapter reseed Node's OpenSSL
// after a snapshot restore (microvm_runtime.mjs).
//
// Node keeps OpenSSL's DRBGs in process memory, so every VM restored from
// one snapshot would draw the same crypto.randomBytes, getRandomValues,
// randomUUID and key material. OpenSSL reseeds a DRBG when its process id
// changes (a fork), which a restore doesn't do, and Node has no JavaScript
// call that reaches RAND_add. This addon is that call: reseed(buf) gives
// OpenSSL's primary DRBG buf (fresh bytes from the guest kernel, which
// /init has reseeded from the host) and makes it reseed from the kernel
// too; the per-thread DRBGs reseed from it before their next output.
//
// A Node-API module, without Node's headers: the few declarations it
// needs are below, and Node's own executable provides every symbol (it
// exports Node-API and OpenSSL's for addons). No libc either, so one build
// loads in any Linux x86-64 image:
//
//   cc -std=c2x -O2 -shared -fPIC -nostdlib -fno-stack-protector
//      -o reseed.node runtimes/js/reseed.c
#include <stddef.h>

typedef struct napi_env__ *napi_env;
typedef struct napi_value__ *napi_value;
typedef struct napi_callback_info__ *napi_callback_info;
typedef napi_value (*napi_callback)(napi_env, napi_callback_info);
typedef int napi_status; // napi_ok is 0

napi_status napi_get_cb_info(napi_env, napi_callback_info, size_t *argc, napi_value *argv,
                             napi_value *this_arg, void **data);
napi_status napi_get_buffer_info(napi_env, napi_value, void **data, size_t *length);
napi_status napi_get_boolean(napi_env, bool, napi_value *);
napi_status napi_create_function(napi_env, const char *name, size_t length, napi_callback, void *data,
                                 napi_value *result);
napi_status napi_set_named_property(napi_env, napi_value object, const char *name, napi_value);
napi_status napi_throw_error(napi_env, const char *code, const char *msg);

// OpenSSL 3, as Node links it.
void RAND_add(const void *buf, int num, double randomness);
int RAND_status(void);

// reseed(buffer): true once OpenSSL's primary DRBG has reseeded.
static napi_value reseed(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value arg, r;
    void *p = nullptr;
    size_t n = 0;
    if (napi_get_cb_info(env, info, &argc, &arg, nullptr, nullptr) || argc != 1 ||
        napi_get_buffer_info(env, arg, &p, &n) || n < 32 || n > 4096) {
        napi_throw_error(env, nullptr, "reseed(buffer): 32 to 4096 fresh random bytes");
        return nullptr;
    }
    RAND_add(p, (int)n, (double)n);
    if (napi_get_boolean(env, RAND_status() == 1, &r))
        return nullptr;
    return r;
}

[[gnu::visibility("default")]] napi_value napi_register_module_v1(napi_env env, napi_value exports);

napi_value napi_register_module_v1(napi_env env, napi_value exports)
{
    napi_value f;
    if (napi_create_function(env, "reseed", 6, reseed, nullptr, &f) ||
        napi_set_named_property(env, exports, "reseed", f))
        return nullptr;
    return exports;
}

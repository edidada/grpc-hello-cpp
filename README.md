gRPC C++ Hello World Tutorial
==============================

# Setup

* Build protobuf from source to install header files, libs & camke files https://github.com/google/protobuf/blob/master/src/README.md
* Then use Clion to open project

# References

* gRPC C++ Quick Start: https://grpc.io/docs/quickstart/cpp.html
* protobuf install: https://github.com/google/protobuf/blob/master/src/README.md
* Clion Protobuf plugin: https://plugins.jetbrains.com/plugin/8277-protobuf-support

### grpc
version
        1.15.1
        
### pb
version
3.6.1

如何使用pb生成cpp文件？
protoc 

protoc -I=protos --cpp_out=protos helloworld.proto
protoc --grpc_out=. --plugin=protoc-gen-grpc=/root/grpc_1.15.1_withoutgit/cmake/build/grpc_cpp_plugin protos/helloworld.proto
生成grpc和protobuf的代码


```cmake
FOREACH(FIL ${protobuf_files})

    GET_FILENAME_COMPONENT(FIL_WE ${FIL} NAME_WE)

    string(REGEX REPLACE ".+/(.+)\\..*" "\\1" FILE_NAME ${FIL})
    string(REGEX REPLACE "(.+)\\${FILE_NAME}.*" "\\1" FILE_PATH ${FIL})

    string(REGEX MATCH "(/mediapipe/framework.*|/mediapipe/util.*|/mediapipe/calculators/internal/)" OUT_PATH ${FILE_PATH})

    set(PROTO_SRCS "${CMAKE_CURRENT_BINARY_DIR}${OUT_PATH}${FIL_WE}.pb.cc")
    set(PROTO_HDRS "${CMAKE_CURRENT_BINARY_DIR}${OUT_PATH}${FIL_WE}.pb.h")

    EXECUTE_PROCESS(
            COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ${PROTO_FLAGS} --cpp_out=${PROTO_META_BASE_DIR} ${FIL}
    )
    message("Copying " ${PROTO_SRCS} " to " ${FILE_PATH})

    file(COPY ${PROTO_SRCS} DESTINATION ${FILE_PATH})
    file(COPY ${PROTO_HDRS} DESTINATION ${FILE_PATH})

ENDFOREACH()
```

cmake 调用protoc grpc_cpp_plugin工具自动生成.h .cpp头文件不会



protoc 生成分离的两个文件 .grpc.pb.h


CMake提供如下命令支持PB
1 find_package(Protobuf REQUIRED)
2 protobuf_generate_cpp

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS caffe.proto)将通过caffe.protof文件生成caffe.pb.h和caffe.pb.cc，生成文件的路径为运行CMakeLists.txt文件所在文件夹。

protoc.exe -I=. --grpc_out=. --plugin=protoc-gen-grpc=.\grpc_cpp_plugin.exe helloworld.proto

```shell script
chmod +x ../script/protoc.sh
#1612850134
ls
#1612850137
cd generated/
#1612850137
ll
#1612850140
ls
#1612850193
which protoc
#1612850349
find . -name "helloworld.pb.cc"
#1612850373
cd grpc-hello-cpp/protos/
#1612850374
ll
#1612850400
cp * /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850426
cat /root/grpc-hello-cpp/cmake-build-debug/generated/helloworld.pb.cc
#1612850448
less /root/grpc-hello-cpp/cmake-build-debug/generated/helloworld.pb.cc
#1612850482
cd /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850484
ll
#1612850491
cd -
#1612850493
pwd
#1612850494
ll
#1612850509
cp helloworld.p.h /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850518
ls
#1612850537
ls-la
#1612850540
ll
#1612850546
cp helloworld.p.h /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850553
cp helloworld.pb.h /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850584
find ~ -name "helloworld.grpc.pb.cc"
#1612850635
cp /root/grpc_1.15.1_withoutgit/examples/cpp/helloworld/helloworld.grpc.pb.cc  /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850648
cp /root/grpc_1.15.1_withoutgit/examples/cpp/helloworld/helloworld.grpc.pb.h  /root/grpc-hello-cpp/cmake-build-debug/generated
#1612850670
find ~ -name "helloworld.grpc.pb.h"
#1612850684
find ~ -name "helloworld.pb.h"
#1612850709
cp /root/grpc-hello-cpp/protos/helloworld.pb.h  /root/grpc-hello-cpp/cmake-build-debug/generated
```

升级openssl
https://www.cnblogs.com/cobcmw/p/11137712.html

```shell script
nm -D /root/openssl-OpenSSL_1_1_1h/libssl.so
                 U ASN1_ANY_it
                 U ASN1_item_d2i
                 U ASN1_item_free
                 U ASN1_item_i2d
                 U ASN1_item_new
                 U ASN1_OCTET_STRING_it
                 U ASN1_TYPE_get
                 U ASYNC_get_current_job
                 U ASYNC_start_job
                 U ASYNC_WAIT_CTX_free
                 U ASYNC_WAIT_CTX_get_all_fds
                 U ASYNC_WAIT_CTX_get_changed_fds
                 U ASYNC_WAIT_CTX_new
                 U BIO_ADDR_clear
                 U BIO_ADDR_free
                 U BIO_ADDR_new
                 U BIO_callback_ctrl
                 U BIO_clear_flags
                 U BIO_copy_next_retry
                 U BIO_ctrl
                 U BIO_dump_indent
                 U BIO_f_buffer
                 U BIO_find_type
                 U BIO_free
                 U BIO_free_all
000000000001e300 T BIO_f_ssl
                 U BIO_get_data
                 U BIO_get_init
                 U BIO_get_retry_reason
                 U BIO_get_shutdown
                 U BIO_int_ctrl
                 U BIO_method_type
                 U BIO_new
000000000001e400 T BIO_new_buffer_ssl_connect
000000000001e310 T BIO_new_ssl
000000000001e390 T BIO_new_ssl_connect
                 U BIO_next
                 U BIO_pop
                 U BIO_printf
                 U BIO_push
                 U BIO_puts
                 U BIO_read
                 U BIO_s_connect
                 U BIO_set_data
                 U BIO_set_flags
                 U BIO_set_init
                 U BIO_set_next
                 U BIO_set_retry_reason
                 U BIO_set_shutdown
                 U BIO_s_file
                 U BIO_s_mem
                 U BIO_snprintf
000000000001e470 T BIO_ssl_copy_session_id
000000000001e4f0 T BIO_ssl_shutdown
                 U BIO_s_socket
                 U BIO_test_flags
                 U BIO_up_ref
                 U BIO_write
                 U BN_bin2bn
                 U BN_bn2bin
                 U BN_clear_free
                 U BN_copy
                 U BN_dup
                 U BN_free
                 U BN_get_rfc2409_prime_1024
                 U BN_get_rfc3526_prime_2048
                 U BN_get_rfc3526_prime_3072
                 U BN_get_rfc3526_prime_4096
                 U BN_get_rfc3526_prime_8192
                 U BN_is_zero
                 U BN_new
                 U BN_num_bits
                 U BN_set_word
                 U BN_ucmp
                 U BUF_MEM_free
                 U BUF_MEM_grow
                 U BUF_MEM_grow_clean
                 U BUF_MEM_new
                 U BUF_reverse
                 U COMP_compress_block
                 U COMP_CTX_free
                 U COMP_CTX_get_method
                 U COMP_CTX_new
                 U COMP_expand_block
                 U COMP_get_name
                 U COMP_get_type
                 U COMP_zlib
                 U CONF_parse_list
                 U conf_ssl_get
                 U conf_ssl_get_cmd
                 U conf_ssl_name_find
                 U CRYPTO_clear_free
                 U CRYPTO_dup_ex_data
                 U CRYPTO_free
                 U CRYPTO_free_ex_data
                 U CRYPTO_get_ex_data
                 U CRYPTO_get_ex_new_index
                 U CRYPTO_malloc
                 U CRYPTO_memcmp
                 U CRYPTO_mem_ctrl
                 U CRYPTO_memdup
                 U CRYPTO_new_ex_data
                 U CRYPTO_realloc
                 U CRYPTO_secure_free
                 U CRYPTO_secure_zalloc
                 U CRYPTO_set_ex_data
                 U CRYPTO_strdup
                 U CRYPTO_strndup
                 U CRYPTO_THREAD_lock_free
                 U CRYPTO_THREAD_lock_new
                 U CRYPTO_THREAD_read_lock
                 U CRYPTO_THREAD_run_once
                 U CRYPTO_THREAD_unlock
                 U CRYPTO_THREAD_write_lock
                 U CRYPTO_zalloc
                 U CTLOG_STORE_free
                 U CTLOG_STORE_load_default_file
                 U CTLOG_STORE_load_file
                 U CTLOG_STORE_new
                 U CT_POLICY_EVAL_CTX_free
                 U CT_POLICY_EVAL_CTX_new
                 U CT_POLICY_EVAL_CTX_set1_cert
                 U CT_POLICY_EVAL_CTX_set1_issuer
                 U CT_POLICY_EVAL_CTX_set_shared_CTLOG_STORE
                 U CT_POLICY_EVAL_CTX_set_time
                 w __cxa_finalize
                 U d2i_OCSP_RESPID
                 U d2i_OCSP_RESPONSE
                 U d2i_PrivateKey
                 U d2i_PrivateKey_bio
                 U d2i_PUBKEY
                 U d2i_RSAPrivateKey
                 U d2i_RSAPrivateKey_bio
000000000002eb40 T d2i_SSL_SESSION
                 U d2i_X509
                 U d2i_X509_bio
                 U d2i_X509_EXTENSIONS
                 U d2i_X509_NAME
                 U DH_check_params
                 U DH_free
                 U DH_get0_key
                 U DH_get0_pqg
                 U DH_new
                 U DH_security_bits
                 U DH_set0_key
                 U DH_set0_pqg
000000000001ff90 T DTLS_client_method
000000000001f910 T DTLS_get_data_mtu
000000000001ff20 T DTLS_method
000000000001ff50 T DTLS_server_method
000000000001f9d0 T DTLS_set_timer_cb
0000000000020050 T DTLSv1_2_client_method
0000000000020030 T DTLSv1_2_method
0000000000020040 T DTLSv1_2_server_method
0000000000020080 T DTLSv1_client_method
000000000001ede0 T DTLSv1_listen
0000000000020060 T DTLSv1_method
0000000000020070 T DTLSv1_server_method
                 U EC_curve_nist2nid
                 U EC_GROUP_get_curve_name
                 U EC_GROUP_method_of
                 U EC_KEY_can_sign
                 U EC_KEY_free
                 U EC_KEY_get0_group
                 U EC_KEY_get_conv_form
                 U EC_KEY_new_by_curve_name
                 U EC_METHOD_get_field_type
                 U ENGINE_finish
                 U ENGINE_get_ssl_client_cert_function
                 U ENGINE_init
                 U ENGINE_load_ssl_client_cert
                 U ERR_add_error_data
                 U ERR_clear_error
                 U err_free_strings_int
                 U ERR_func_error_string
0000000000036530 T ERR_load_SSL_strings
                 U ERR_load_strings_const
                 U __errno_location
                 U ERR_peek_error
                 U ERR_peek_last_error
                 U ERR_pop_to_mark
                 U ERR_put_error
                 U ERR_set_mark
                 U EVP_add_cipher
                 U EVP_add_digest
                 U EVP_aes_128_cbc
                 U EVP_aes_128_cbc_hmac_sha1
                 U EVP_aes_128_cbc_hmac_sha256
                 U EVP_aes_128_ccm
                 U EVP_aes_128_gcm
                 U EVP_aes_192_cbc
                 U EVP_aes_256_cbc
                 U EVP_aes_256_cbc_hmac_sha1
                 U EVP_aes_256_cbc_hmac_sha256
                 U EVP_aes_256_ccm
                 U EVP_aes_256_gcm
                 U EVP_aria_128_gcm
                 U EVP_aria_256_gcm
                 U EVP_camellia_128_cbc
                 U EVP_camellia_256_cbc
                 U EVP_chacha20_poly1305
                 U EVP_Cipher
                 U EVP_CIPHER_block_size
                 U EVP_CIPHER_CTX_block_size
                 U EVP_CIPHER_CTX_cipher
                 U EVP_CIPHER_CTX_ctrl
                 U EVP_CIPHER_CTX_free
                 U EVP_CIPHER_CTX_iv_length
                 U EVP_CIPHER_CTX_new
                 U EVP_CIPHER_CTX_reset
                 U EVP_CipherFinal_ex
                 U EVP_CIPHER_flags
                 U EVP_CipherInit_ex
                 U EVP_CIPHER_iv_length
                 U EVP_CIPHER_key_length
                 U EVP_CipherUpdate
                 U EVP_DecryptFinal
                 U EVP_DecryptInit_ex
                 U EVP_DecryptUpdate
                 U EVP_des_cbc
                 U EVP_des_ede3_cbc
                 U EVP_Digest
                 U EVP_DigestFinal
                 U EVP_DigestFinal_ex
                 U EVP_DigestInit
                 U EVP_DigestInit_ex
                 U EVP_DigestSign
                 U EVP_DigestSignFinal
                 U EVP_DigestSignInit
                 U EVP_DigestUpdate
                 U EVP_DigestVerify
                 U EVP_DigestVerifyFinal
                 U EVP_DigestVerifyInit
                 U EVP_enc_null
                 U EVP_EncryptFinal
                 U EVP_EncryptInit_ex
                 U EVP_EncryptUpdate
                 U EVP_get_cipherbyname
                 U EVP_get_digestbyname
                 U EVP_idea_cbc
                 U EVP_md5
                 U EVP_md5_sha1
                 U EVP_MD_CTX_copy
                 U EVP_MD_CTX_copy_ex
                 U EVP_MD_CTX_ctrl
                 U EVP_MD_CTX_free
                 U EVP_MD_CTX_md
                 U EVP_MD_CTX_new
                 U EVP_MD_CTX_set_flags
                 U EVP_MD_size
                 U EVP_MD_type
                 U EVP_PKEY_asn1_find_str
                 U EVP_PKEY_asn1_get0_info
                 U EVP_PKEY_assign
                 U EVP_PKEY_cmp
                 U EVP_PKEY_copy_parameters
                 U EVP_PKEY_CTX_ctrl
                 U EVP_PKEY_CTX_free
                 U EVP_PKEY_CTX_new
                 U EVP_PKEY_CTX_new_id
                 U EVP_PKEY_decrypt
                 U EVP_PKEY_decrypt_init
                 U EVP_PKEY_derive
                 U EVP_PKEY_derive_init
                 U EVP_PKEY_derive_set_peer
                 U EVP_PKEY_encrypt
                 U EVP_PKEY_encrypt_init
                 U EVP_PKEY_free
                 U EVP_PKEY_get0
                 U EVP_PKEY_get0_DH
                 U EVP_PKEY_get0_EC_KEY
                 U EVP_PKEY_get0_RSA
                 U EVP_PKEY_get1_tls_encodedpoint
                 U EVP_PKEY_get_default_digest_nid
                 U EVP_PKEY_id
                 U EVP_PKEY_keygen
                 U EVP_PKEY_keygen_init
                 U EVP_PKEY_missing_parameters
                 U EVP_PKEY_new
                 U EVP_PKEY_new_mac_key
                 U EVP_PKEY_new_raw_private_key
                 U EVP_PKEY_paramgen
                 U EVP_PKEY_paramgen_init
                 U EVP_PKEY_security_bits
                 U EVP_PKEY_set1_DH
                 U EVP_PKEY_set1_tls_encodedpoint
                 U EVP_PKEY_set_type
                 U EVP_PKEY_size
                 U EVP_PKEY_up_ref
                 U EVP_rc2_40_cbc
                 U EVP_rc2_cbc
                 U EVP_rc4
                 U EVP_rc4_hmac_md5
                 U EVP_seed_cbc
                 U EVP_sha1
                 U EVP_sha224
                 U EVP_sha256
                 U EVP_sha384
                 U EVP_sha512
                 U gettimeofday
                 w __gmon_start__
                 U HMAC_CTX_free
                 U HMAC_CTX_new
                 U HMAC_Final
                 U HMAC_Init_ex
                 U HMAC_size
                 U HMAC_Update
                 U i2d_OCSP_RESPID
000000000002e6c0 T i2d_SSL_SESSION
                 U i2d_X509
                 U i2d_X509_EXTENSIONS
                 U i2d_X509_NAME
                 U INT32_it
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
                 U MD5_Init
                 U MD5_Transform
                 U memchr
                 U memcmp
                 U memcpy
                 U memmove
                 U memset
                 U o2i_SCT_LIST
                 U OBJ_bsearch_
                 U OBJ_ln2nid
                 U OBJ_NAME_add
                 U OBJ_nid2sn
                 U OBJ_sn2nid
                 U OCSP_BASICRESP_free
                 U OCSP_resp_count
                 U OCSP_resp_get0
                 U OCSP_RESPID_free
                 U OCSP_RESPONSE_free
                 U OCSP_response_get1_basic
                 U OCSP_SINGLERESP_get1_ext_d2i
0000000000000000 A OPENSSL_1_1_0
0000000000000000 A OPENSSL_1_1_0d
0000000000000000 A OPENSSL_1_1_1
0000000000000000 A OPENSSL_1_1_1a
                 U OPENSSL_atexit
0000000000033c20 T OPENSSL_cipher_name
                 U OPENSSL_cleanse
                 U OPENSSL_DIR_end
                 U OPENSSL_DIR_read
                 U OPENSSL_init_crypto
0000000000036850 T OPENSSL_init_ssl
                 U OPENSSL_LH_delete
                 U OPENSSL_LH_doall_arg
                 U OPENSSL_LH_free
                 U OPENSSL_LH_get_down_load
                 U OPENSSL_LH_insert
                 U OPENSSL_LH_new
                 U OPENSSL_LH_num_items
                 U OPENSSL_LH_retrieve
                 U OPENSSL_LH_set_down_load
                 U OPENSSL_sk_delete
                 U OPENSSL_sk_dup
                 U OPENSSL_sk_find
                 U OPENSSL_sk_free
                 U OPENSSL_sk_insert
                 U OPENSSL_sk_new
                 U OPENSSL_sk_new_null
                 U OPENSSL_sk_new_reserve
                 U OPENSSL_sk_num
                 U OPENSSL_sk_pop
                 U OPENSSL_sk_pop_free
                 U OPENSSL_sk_push
                 U OPENSSL_sk_set_cmp_func
                 U OPENSSL_sk_shift
                 U OPENSSL_sk_sort
                 U OPENSSL_sk_value
                 U PEM_ASN1_read
                 U PEM_ASN1_read_bio
                 U PEM_ASN1_write
                 U PEM_ASN1_write_bio
                 U PEM_read_bio
                 U PEM_read_bio_DHparams
                 U PEM_read_bio_PrivateKey
                 U PEM_read_bio_RSAPrivateKey
0000000000044d10 T PEM_read_bio_SSL_SESSION
                 U PEM_read_bio_X509
                 U PEM_read_bio_X509_AUX
0000000000044d30 T PEM_read_SSL_SESSION
0000000000044d50 T PEM_write_bio_SSL_SESSION
0000000000044d80 T PEM_write_SSL_SESSION
                 U qsort
                 U RAND_bytes
                 U RAND_priv_bytes
                 U RSA_free
                 U RSA_pkey_ctx_ctrl
                 U RSA_private_decrypt
                 U RSA_size
                 U RSA_up_ref
                 U SCT_get_validation_status
                 U SCT_LIST_free
                 U SCT_LIST_validate
                 U SCT_set_source
                 U SHA1_Init
                 U SHA1_Transform
                 U SHA224_Init
                 U SHA256_Init
                 U SHA256_Transform
                 U SHA384_Init
                 U SHA512_Init
                 U SHA512_Transform
                 U sprintf
                 U SRP_Calc_A
000000000006c210 T SRP_Calc_A_param
                 U SRP_Calc_B
                 U SRP_Calc_client_key
                 U SRP_Calc_server_key
                 U SRP_Calc_u
                 U SRP_Calc_x
                 U SRP_check_known_gN_param
                 U SRP_create_verifier_BN
                 U SRP_get_default_gN
                 U SRP_Verify_A_mod_N
                 U SRP_Verify_B_mod_N
000000000003ca50 T SSL_accept
0000000000037070 T SSL_add1_host
0000000000030670 T SSL_add1_to_CA_list
00000000000307b0 T SSL_add_client_CA
0000000000030c40 T SSL_add_dir_cert_subjects_to_stack
0000000000030ae0 T SSL_add_file_cert_subjects_to_stack
000000000003fc30 T SSL_add_ssl_module
00000000000452d0 T SSL_alert_desc_string
00000000000454e0 T SSL_alert_desc_string_long
00000000000452a0 T SSL_alert_type_string
0000000000045270 T SSL_alert_type_string_long
000000000003ed50 T SSL_alloc_buffers
000000000003f800 T SSL_bytes_to_cipher_list
0000000000039aa0 T SSL_callback_ctrl
0000000000037e80 T SSL_certs_clear
0000000000068db0 T SSL_check_chain
00000000000385d0 T SSL_check_private_key
0000000000033630 T SSL_CIPHER_description
0000000000033f90 T SSL_CIPHER_find
00000000000341c0 T SSL_CIPHER_get_auth_nid
0000000000033c50 T SSL_CIPHER_get_bits
0000000000033fa0 T SSL_CIPHER_get_cipher_nid
0000000000033fe0 T SSL_CIPHER_get_digest_nid
0000000000034290 T SSL_CIPHER_get_handshake_digest
0000000000033c70 T SSL_CIPHER_get_id
00000000000340d0 T SSL_CIPHER_get_kx_nid
0000000000033be0 T SSL_CIPHER_get_name
0000000000033c80 T SSL_CIPHER_get_protocol_id
0000000000033bb0 T SSL_CIPHER_get_version
00000000000342b0 T SSL_CIPHER_is_aead
0000000000033c00 T SSL_CIPHER_standard_name
000000000003c730 T SSL_clear
000000000003d470 T SSL_clear_options
000000000003e810 T SSL_client_hello_get0_ciphers
000000000003e840 T SSL_client_hello_get0_compression_methods
000000000003eca0 T SSL_client_hello_get0_ext
000000000003e7a0 T SSL_client_hello_get0_legacy_version
000000000003e7c0 T SSL_client_hello_get0_random
000000000003e7f0 T SSL_client_hello_get0_session_id
000000000003e870 T SSL_client_hello_get1_extensions_present
000000000003e780 T SSL_client_hello_isv2
000000000003bc00 T SSL_client_version
0000000000033d60 T SSL_COMP_add_compression_method
0000000000033f40 T SSL_COMP_get0_name
0000000000033d00 T SSL_COMP_get_compression_methods
0000000000033f50 T SSL_COMP_get_id
0000000000033f20 T SSL_COMP_get_name
0000000000033d30 T SSL_COMP_set0_compression_methods
0000000000035930 T SSL_CONF_cmd
0000000000035be0 T SSL_CONF_cmd_argv
0000000000035ca0 T SSL_CONF_cmd_value_type
0000000000036350 T SSL_CONF_CTX_clear_flags
0000000000035d80 T SSL_CONF_CTX_finish
00000000000362a0 T SSL_CONF_CTX_free
0000000000035d60 T SSL_CONF_CTX_new
0000000000036360 T SSL_CONF_CTX_set1_prefix
0000000000036340 T SSL_CONF_CTX_set_flags
0000000000036400 T SSL_CONF_CTX_set_ssl
00000000000364a0 T SSL_CONF_CTX_set_ssl_ctx
000000000003fc40 T SSL_config
000000000003cc50 T SSL_connect
0000000000038490 T SSL_copy_session_id
000000000003e430 T SSL_ct_is_enabled
0000000000039510 T SSL_ctrl
0000000000030710 T SSL_CTX_add1_to_CA_list
0000000000030850 T SSL_CTX_add_client_CA
000000000004c2a0 T SSL_CTX_add_client_custom_ext
000000000004c150 T SSL_CTX_add_custom_ext
000000000004bf20 T SSL_CTX_add_server_custom_ext
0000000000043b50 T SSL_CTX_add_session
0000000000039fb0 T SSL_CTX_callback_ctrl
0000000000038540 T SSL_CTX_check_private_key
000000000003d450 T SSL_CTX_clear_options
000000000003fe60 T SSL_CTX_config
000000000003e440 T SSL_CTX_ct_is_enabled
0000000000039ad0 T SSL_CTX_ctrl
00000000000371d0 T SSL_CTX_dane_clear_flags
00000000000370a0 T SSL_CTX_dane_enable
0000000000037a10 T SSL_CTX_dane_mtype_set
00000000000371b0 T SSL_CTX_dane_set_flags
000000000003e650 T SSL_CTX_enable_ct
0000000000044990 T SSL_CTX_flush_sessions
000000000003a910 T SSL_CTX_free
0000000000030560 T SSL_CTX_get0_CA_list
000000000003b700 T SSL_CTX_get0_certificate
000000000003e760 T SSL_CTX_get0_ctlog_store
0000000000037e60 T SSL_CTX_get0_param
000000000003b720 T SSL_CTX_get0_privatekey
000000000003d400 T SSL_CTX_get0_security_ex_data
000000000003c090 T SSL_CTX_get_cert_store
000000000003a1d0 T SSL_CTX_get_ciphers
00000000000305c0 T SSL_CTX_get_client_CA_list
0000000000044b70 T SSL_CTX_get_client_cert_cb
000000000003afb0 T SSL_CTX_get_default_passwd_cb
000000000003afc0 T SSL_CTX_get_default_passwd_cb_userdata
000000000003c080 T SSL_CTX_get_ex_data
0000000000044b50 T SSL_CTX_get_info_callback
000000000003ed70 T SSL_CTX_get_keylog_callback
000000000003f850 T SSL_CTX_get_max_early_data
000000000003c700 T SSL_CTX_get_num_tickets
000000000003d410 T SSL_CTX_get_options
000000000003b8b0 T SSL_CTX_get_quiet_shutdown
000000000003c610 T SSL_CTX_get_record_padding_callback_arg
000000000003f890 T SSL_CTX_get_recv_max_early_data
000000000003d3e0 T SSL_CTX_get_security_callback
000000000003d3c0 T SSL_CTX_get_security_level
000000000003b2d0 T SSL_CTX_get_ssl_method
0000000000044850 T SSL_CTX_get_timeout
0000000000038360 T SSL_CTX_get_verify_callback
0000000000038350 T SSL_CTX_get_verify_depth
0000000000038340 T SSL_CTX_get_verify_mode
000000000004be70 T SSL_CTX_has_client_custom_ext
000000000003be10 T SSL_CTX_load_verify_locations
000000000003aaf0 T SSL_CTX_new
0000000000043990 T SSL_CTX_remove_session
0000000000044b30 T SSL_CTX_sess_get_get_cb
0000000000044af0 T SSL_CTX_sess_get_new_cb
0000000000044b10 T SSL_CTX_sess_get_remove_cb
0000000000039ac0 T SSL_CTX_sessions
0000000000044b20 T SSL_CTX_sess_set_get_cb
0000000000044ae0 T SSL_CTX_sess_set_new_cb
0000000000044b00 T SSL_CTX_sess_set_remove_cb
0000000000030530 T SSL_CTX_set0_CA_list
000000000003e730 T SSL_CTX_set0_ctlog_store
000000000003d3f0 T SSL_CTX_set0_security_ex_data
000000000003c0c0 T SSL_CTX_set1_cert_store
0000000000037e40 T SSL_CTX_set1_param
000000000003fc10 T SSL_CTX_set_allow_early_data_cb
000000000003a710 T SSL_CTX_set_alpn_protos
000000000003a830 T SSL_CTX_set_alpn_select_cb
000000000003c620 T SSL_CTX_set_block_padding
000000000003b040 T SSL_CTX_set_cert_cb
000000000003c0a0 T SSL_CTX_set_cert_store
000000000003b010 T SSL_CTX_set_cert_verify_callback
000000000003a1f0 T SSL_CTX_set_cipher_list
0000000000032b10 T SSL_CTX_set_ciphersuites
0000000000030590 T SSL_CTX_set_client_CA_list
0000000000044b60 T SSL_CTX_set_client_cert_cb
0000000000044b80 T SSL_CTX_set_client_cert_engine
000000000003e770 T SSL_CTX_set_client_hello_cb
0000000000044c20 T SSL_CTX_set_cookie_generate_cb
0000000000044c30 T SSL_CTX_set_cookie_verify_cb
000000000003e720 T SSL_CTX_set_ctlog_list_file
000000000003e3c0 T SSL_CTX_set_ct_validation_callback
000000000003e710 T SSL_CTX_set_default_ctlog_list_file
000000000003af90 T SSL_CTX_set_default_passwd_cb
000000000003afa0 T SSL_CTX_set_default_passwd_cb_userdata
0000000000022930 T SSL_CTX_set_default_read_buffer_len
000000000003bd70 T SSL_CTX_set_default_verify_dir
000000000003bdc0 T SSL_CTX_set_default_verify_file
000000000003bd60 T SSL_CTX_set_default_verify_paths
000000000003c070 T SSL_CTX_set_ex_data
0000000000036e90 T SSL_CTX_set_generate_session_id
0000000000044b40 T SSL_CTX_set_info_callback
000000000003ed60 T SSL_CTX_set_keylog_callback
000000000003f840 T SSL_CTX_set_max_early_data
000000000003c5b0 T SSL_CTX_set_msg_callback
000000000003a6f0 T SSL_CTX_set_next_protos_advertised_cb
000000000003a700 T SSL_CTX_set_next_proto_select_cb
000000000003c5d0 T SSL_CTX_set_not_resumable_session_callback
000000000003c6f0 T SSL_CTX_set_num_tickets
000000000003d430 T SSL_CTX_set_options
000000000003f9b0 T SSL_CTX_set_post_handshake_auth
000000000003c540 T SSL_CTX_set_psk_client_callback
000000000003c580 T SSL_CTX_set_psk_find_session_callback
000000000003c560 T SSL_CTX_set_psk_server_callback
000000000003c5a0 T SSL_CTX_set_psk_use_session_callback
0000000000037020 T SSL_CTX_set_purpose
000000000003b8a0 T SSL_CTX_set_quiet_shutdown
000000000003c5f0 T SSL_CTX_set_record_padding_callback
000000000003c600 T SSL_CTX_set_record_padding_callback_arg
000000000003f880 T SSL_CTX_set_recv_max_early_data
000000000003d3d0 T SSL_CTX_set_security_callback
000000000003d3b0 T SSL_CTX_set_security_level
0000000000036cd0 T SSL_CTX_set_session_id_context
000000000003fbf0 T SSL_CTX_set_session_ticket_cb
000000000006c390 T SSL_CTX_set_srp_cb_arg
000000000006c3d0 T SSL_CTX_set_srp_client_pwd_callback
000000000006c330 T SSL_CTX_set_srp_password
000000000006c350 T SSL_CTX_set_srp_strength
000000000006c310 T SSL_CTX_set_srp_username
000000000006c3b0 T SSL_CTX_set_srp_username_callback
000000000006c370 T SSL_CTX_set_srp_verify_param_callback
0000000000036bd0 T SSL_CTX_set_ssl_version
0000000000044cf0 T SSL_CTX_set_stateless_cookie_generate_cb
0000000000044d00 T SSL_CTX_set_stateless_cookie_verify_cb
0000000000044830 T SSL_CTX_set_timeout
0000000000069720 T SSL_CTX_set_tlsext_max_fragment_length
000000000001fd80 T SSL_CTX_set_tlsext_use_srtp
000000000003c2c0 T SSL_CTX_set_tmp_dh_callback
0000000000037040 T SSL_CTX_set_trust
000000000003b020 T SSL_CTX_set_verify
000000000003b030 T SSL_CTX_set_verify_depth
000000000006b410 T SSL_CTX_SRP_CTX_free
000000000006b930 T SSL_CTX_SRP_CTX_init
000000000003a8f0 T SSL_CTX_up_ref
0000000000042ad0 T SSL_CTX_use_cert_and_key
0000000000041030 T SSL_CTX_use_certificate
00000000000413c0 T SSL_CTX_use_certificate_ASN1
0000000000041bc0 T SSL_CTX_use_certificate_chain_file
0000000000041270 T SSL_CTX_use_certificate_file
0000000000041850 T SSL_CTX_use_PrivateKey
0000000000041b50 T SSL_CTX_use_PrivateKey_ASN1
00000000000419e0 T SSL_CTX_use_PrivateKey_file
000000000003c2e0 T SSL_CTX_use_psk_identity_hint
0000000000041440 T SSL_CTX_use_RSAPrivateKey
00000000000417e0 T SSL_CTX_use_RSAPrivateKey_ASN1
0000000000041670 T SSL_CTX_use_RSAPrivateKey_file
0000000000042270 T SSL_CTX_use_serverinfo
0000000000041f90 T SSL_CTX_use_serverinfo_ex
0000000000042280 T SSL_CTX_use_serverinfo_file
0000000000037210 T SSL_dane_clear_flags
0000000000039930 T SSL_dane_enable
00000000000371f0 T SSL_dane_set_flags
00000000000373b0 T SSL_dane_tlsa_add
000000000003b380 T SSL_do_handshake
000000000003dea0 T SSL_dup
0000000000030440 T SSL_dup_CA_list
000000000003e6b0 T SSL_enable_ct
000000000003a880 T SSL_export_keying_material
000000000003a8d0 T SSL_export_keying_material_early
000000000004bea0 T SSL_extension_supported
000000000003ce60 T SSL_free
000000000003ed10 T SSL_free_buffers
000000000003a840 T SSL_get0_alpn_selected
0000000000030570 T SSL_get0_CA_list
00000000000373a0 T SSL_get0_dane
0000000000037230 T SSL_get0_dane_authority
00000000000372c0 T SSL_get0_dane_tlsa
000000000003a6d0 T SSL_get0_next_proto_negotiated
0000000000037e70 T SSL_get0_param
0000000000030600 T SSL_get0_peer_CA_list
0000000000037090 T SSL_get0_peername
000000000003d4c0 T SSL_get0_peer_scts
000000000003d3a0 T SSL_get0_security_ex_data
000000000003d490 T SSL_get0_verified_chain
0000000000043b10 T SSL_get1_session
000000000003a080 T SSL_get1_supported_ciphers
00000000000386a0 T SSL_get_all_async_fds
000000000003b6c0 T SSL_get_certificate
00000000000386c0 T SSL_get_changed_async_fds
000000000003a170 T SSL_get_cipher_list
000000000003a020 T SSL_get_ciphers
0000000000030620 T SSL_get_client_CA_list
000000000003a060 T SSL_get_client_ciphers
000000000003be60 T SSL_get_client_random
000000000003b740 T SSL_get_current_cipher
000000000003b770 T SSL_get_current_compression
000000000003b790 T SSL_get_current_expansion
000000000003aff0 T SSL_get_default_passwd_cb
000000000003b000 T SSL_get_default_passwd_cb_userdata
00000000000386e0 T SSL_get_default_timeout
00000000000389a0 T SSL_get_early_data_status
000000000003c100 T SSL_get_error
000000000003c060 T SSL_get_ex_data
000000000002f640 T SSL_get_ex_data_X509_STORE_CTX_idx
0000000000038040 T SSL_get_fd
0000000000038290 T SSL_get_finished
000000000003be30 T SSL_get_info_callback
0000000000039390 T SSL_get_key_update_type
000000000003f870 T SSL_get_max_early_data
000000000003c6e0 T SSL_get_num_tickets
000000000003d420 T SSL_get_options
0000000000038460 T SSL_get_peer_cert_chain
0000000000038420 T SSL_get_peer_certificate
00000000000382d0 T SSL_get_peer_finished
0000000000066310 T SSL_get_peer_signature_type_nid
000000000003b760 T SSL_get_pending_cipher
000000000003b6e0 T SSL_get_privatekey
000000000003c500 T SSL_get_psk_identity
000000000003c4d0 T SSL_get_psk_identity_hint
000000000003b8d0 T SSL_get_quiet_shutdown
0000000000037f00 T SSL_get_rbio
00000000000383b0 T SSL_get_read_ahead
000000000003c680 T SSL_get_record_padding_callback_arg
000000000003f8b0 T SSL_get_recv_max_early_data
0000000000038000 T SSL_get_rfd
000000000003d380 T SSL_get_security_callback
000000000003d360 T SSL_get_security_level
000000000001fe00 T SSL_get_selected_srtp_profile
000000000003a480 T SSL_get_servername
000000000003a580 T SSL_get_servername_type
000000000003bf20 T SSL_get_server_random
0000000000042e70 T SSL_get_session
000000000003a340 T SSL_get_shared_ciphers
0000000000068080 T SSL_get_shared_sigalgs
000000000003b8f0 T SSL_get_shutdown
0000000000067f70 T SSL_get_sigalgs
0000000000066340 T SSL_get_signature_type_nid
000000000006c290 T SSL_get_srp_g
000000000006c2b0 T SSL_get_srp_N
000000000006c2f0 T SSL_get_srp_userinfo
000000000006c2d0 T SSL_get_srp_username
000000000001fdc0 T SSL_get_srtp_profiles
000000000003bc10 T SSL_get_SSL_CTX
000000000003b2e0 T SSL_get_ssl_method
000000000004fe80 T SSL_get_state
0000000000038330 T SSL_get_verify_callback
0000000000038320 T SSL_get_verify_depth
0000000000038310 T SSL_get_verify_mode
000000000003be50 T SSL_get_verify_result
000000000003b640 T SSL_get_version
0000000000037f10 T SSL_get_wbio
0000000000038050 T SSL_get_wfd
0000000000036f10 T SSL_has_matching_session_id
00000000000383f0 T SSL_has_pending
000000000004fec0 T SSL_in_before
000000000004fe90 T SSL_in_init
0000000000036c90 T SSL_is_dtls
000000000004fea0 T SSL_is_init_finished
000000000003d330 T SSL_is_server
00000000000392a0 T SSL_key_update
00000000000308f0 T SSL_load_client_CA_file
000000000003d910 T SSL_new
00000000000389b0 T SSL_peek
0000000000038bd0 T SSL_peek_ex
00000000000383c0 T SSL_pending
0000000000038930 T SSL_read
000000000003ca80 T SSL_read_early_data
0000000000038980 T SSL_read_ex
00000000000393a0 T SSL_renegotiate
0000000000039450 T SSL_renegotiate_abbreviated
0000000000039500 T SSL_renegotiate_pending
0000000000022990 T SSL_rstate_string
0000000000022950 T SSL_rstate_string_long
000000000003a5a0 T SSL_select_next_proto
00000000000436d0 T SSL_SESSION_dup
0000000000043230 T SSL_SESSION_free
0000000000044630 T SSL_SESSION_get0_alpn_selected
0000000000044530 T SSL_SESSION_get0_cipher
0000000000044550 T SSL_SESSION_get0_hostname
0000000000043000 T SSL_SESSION_get0_id_context
00000000000446f0 T SSL_SESSION_get0_peer
00000000000445f0 T SSL_SESSION_get0_ticket
0000000000044cd0 T SSL_SESSION_get0_ticket_appdata
0000000000043020 T SSL_SESSION_get_compress_id
0000000000042e90 T SSL_SESSION_get_ex_data
0000000000042fe0 T SSL_SESSION_get_id
000000000003bfe0 T SSL_SESSION_get_master_key
0000000000044610 T SSL_SESSION_get_max_early_data
00000000000697c0 T SSL_SESSION_get_max_fragment_length
0000000000044510 T SSL_SESSION_get_protocol_version
00000000000445e0 T SSL_SESSION_get_ticket_lifetime_hint
00000000000444e0 T SSL_SESSION_get_time
00000000000444d0 T SSL_SESSION_get_timeout
00000000000445d0 T SSL_SESSION_has_ticket
0000000000044800 T SSL_SESSION_is_resumable
0000000000042ea0 T SSL_SESSION_new
0000000000045700 T SSL_SESSION_print
0000000000045c00 T SSL_SESSION_print_fp
0000000000045c80 T SSL_SESSION_print_keylog
000000000003d320 T SSL_session_reused
0000000000044650 T SSL_SESSION_set1_alpn_selected
0000000000044560 T SSL_SESSION_set1_hostname
00000000000443b0 T SSL_SESSION_set1_id
0000000000044700 T SSL_SESSION_set1_id_context
000000000003c010 T SSL_SESSION_set1_master_key
0000000000044c40 T SSL_SESSION_set1_ticket_appdata
0000000000044540 T SSL_SESSION_set_cipher
0000000000042e80 T SSL_SESSION_set_ex_data
0000000000044620 T SSL_SESSION_set_max_early_data
0000000000044520 T SSL_SESSION_set_protocol_version
00000000000444f0 T SSL_SESSION_set_time
00000000000444b0 T SSL_SESSION_set_timeout
0000000000043af0 T SSL_SESSION_up_ref
0000000000030500 T SSL_set0_CA_list
0000000000037e90 T SSL_set0_rbio
000000000003d390 T SSL_set0_security_ex_data
0000000000037eb0 T SSL_set0_wbio
0000000000037060 T SSL_set1_host
0000000000037e50 T SSL_set1_param
000000000003ca00 T SSL_set_accept_state
000000000003fc20 T SSL_set_allow_early_data_cb
000000000003a7a0 T SSL_set_alpn_protos
0000000000037f30 T SSL_set_bio
000000000003c690 T SSL_set_block_padding
000000000003b050 T SSL_set_cert_cb
000000000003a290 T SSL_set_cipher_list
0000000000032bc0 T SSL_set_ciphersuites
00000000000305d0 T SSL_set_client_CA_list
000000000003cc00 T SSL_set_connect_state
000000000003d870 T SSL_set_ct_validation_callback
000000000003d340 T SSL_set_debug
000000000003afd0 T SSL_set_default_passwd_cb
000000000003afe0 T SSL_set_default_passwd_cb_userdata
0000000000022940 T SSL_set_default_read_buffer_len
000000000003c050 T SSL_set_ex_data
0000000000038090 T SSL_set_fd
0000000000036ed0 T SSL_set_generate_session_id
0000000000037080 T SSL_set_hostflags
000000000003be20 T SSL_set_info_callback
000000000003f860 T SSL_set_max_early_data
000000000003c5c0 T SSL_set_msg_callback
000000000003c5e0 T SSL_set_not_resumable_session_callback
000000000003c6d0 T SSL_set_num_tickets
000000000003d440 T SSL_set_options
000000000003f9c0 T SSL_set_post_handshake_auth
000000000003c530 T SSL_set_psk_client_callback
000000000003c570 T SSL_set_psk_find_session_callback
000000000003c550 T SSL_set_psk_server_callback
000000000003c590 T SSL_set_psk_use_session_callback
0000000000037030 T SSL_set_purpose
000000000003b8c0 T SSL_set_quiet_shutdown
00000000000383a0 T SSL_set_read_ahead
000000000003c660 T SSL_set_record_padding_callback
000000000003c670 T SSL_set_record_padding_callback_arg
000000000003f8a0 T SSL_set_recv_max_early_data
00000000000381d0 T SSL_set_rfd
000000000003d370 T SSL_set_security_callback
000000000003d350 T SSL_set_security_level
0000000000044a70 T SSL_set_session
0000000000036db0 T SSL_set_session_id_context
0000000000044860 T SSL_set_session_secret_cb
00000000000448a0 T SSL_set_session_ticket_ext
0000000000044880 T SSL_set_session_ticket_ext_cb
000000000003b8e0 T SSL_set_shutdown
000000000006bb30 T SSL_set_srp_server_param
000000000006ba70 T SSL_set_srp_server_param_pw
000000000003bc20 T SSL_set_SSL_CTX
000000000003b2f0 T SSL_set_ssl_method
0000000000069770 T SSL_set_tlsext_max_fragment_length
000000000001fda0 T SSL_set_tlsext_use_srtp
000000000003c2d0 T SSL_set_tmp_dh_callback
0000000000037050 T SSL_set_trust
0000000000038370 T SSL_set_verify
0000000000038390 T SSL_set_verify_depth
000000000003be40 T SSL_set_verify_result
0000000000038110 T SSL_set_wfd
00000000000390d0 T SSL_shutdown
000000000006b500 T SSL_SRP_CTX_free
000000000006b5f0 T SSL_SRP_CTX_init
000000000006b980 T SSL_srp_server_param_with_username
000000000003f940 T SSL_stateless
0000000000045010 T SSL_state_string
0000000000044db0 T SSL_state_string_long
0000000000036cb0 T SSL_up_ref
0000000000042790 T SSL_use_cert_and_key
00000000000404b0 T SSL_use_certificate
0000000000040830 T SSL_use_certificate_ASN1
0000000000041db0 T SSL_use_certificate_chain_file
00000000000406e0 T SSL_use_certificate_file
0000000000040cc0 T SSL_use_PrivateKey
0000000000040fc0 T SSL_use_PrivateKey_ASN1
0000000000040e50 T SSL_use_PrivateKey_file
000000000003c3d0 T SSL_use_psk_identity_hint
00000000000408b0 T SSL_use_RSAPrivateKey
0000000000040c50 T SSL_use_RSAPrivateKey_ASN1
0000000000040ae0 T SSL_use_RSAPrivateKey_file
000000000003f9d0 T SSL_verify_client_post_handshake
000000000003b900 T SSL_version
0000000000038690 T SSL_waiting_for_async
000000000003c0f0 T SSL_want
0000000000039060 T SSL_write
000000000003cc80 T SSL_write_early_data
00000000000390b0 T SSL_write_ex
                 U strcasecmp
                 U strchr
                 U strcmp
                 U strcpy
                 U strlen
                 U strncasecmp
                 U strncmp
                 U strtol
                 U time
000000000001feb0 T TLS_client_method
000000000001fe10 T TLS_method
000000000001fe60 T TLS_server_method
000000000001fff0 T TLSv1_1_client_method
000000000001ffd0 T TLSv1_1_method
000000000001ffe0 T TLSv1_1_server_method
000000000001ffc0 T TLSv1_2_client_method
000000000001ffa0 T TLSv1_2_method
000000000001ffb0 T TLSv1_2_server_method
0000000000020020 T TLSv1_client_method
0000000000020000 T TLSv1_method
0000000000020010 T TLSv1_server_method
                 U UINT32_it
                 U X509_chain_check_suiteb
                 U X509_chain_up_ref
                 U X509_check_private_key
                 U X509_cmp
                 U X509_EXTENSION_free
                 U X509_free
                 U X509_get0_pubkey
                 U X509_get_ext_d2i
                 U X509_get_extension_flags
                 U X509_get_issuer_name
                 U X509_get_key_usage
                 U X509_get_pubkey
                 U X509_get_signature_info
                 U X509_get_signature_nid
                 U X509_get_subject_name
                 U X509_it
                 U X509_LOOKUP_ctrl
                 U X509_LOOKUP_file
                 U X509_LOOKUP_hash_dir
                 U X509_NAME_cmp
                 U X509_NAME_dup
                 U X509_NAME_free
                 U X509_NAME_hash
                 U X509_STORE_add_cert
                 U X509_STORE_add_lookup
                 U X509_STORE_CTX_free
                 U X509_STORE_CTX_get0_chain
                 U X509_STORE_CTX_get0_param
                 U X509_STORE_CTX_get1_chain
                 U X509_STORE_CTX_get_error
                 U X509_STORE_CTX_init
                 U X509_STORE_CTX_new
                 U X509_STORE_CTX_set0_dane
                 U X509_STORE_CTX_set_default
                 U X509_STORE_CTX_set_ex_data
                 U X509_STORE_CTX_set_flags
                 U X509_STORE_CTX_set_verify_cb
                 U X509_STORE_free
                 U X509_STORE_load_locations
                 U X509_STORE_new
                 U X509_STORE_set_default_paths
                 U X509_STORE_up_ref
                 U X509_up_ref
                 U X509_verify_cert
                 U X509_verify_cert_error_string
                 U X509_VERIFY_PARAM_add1_host
                 U X509_VERIFY_PARAM_free
                 U X509_VERIFY_PARAM_get0_peername
                 U X509_VERIFY_PARAM_get_depth
                 U X509_VERIFY_PARAM_inherit
                 U X509_VERIFY_PARAM_move_peername
                 U X509_VERIFY_PARAM_new
                 U X509_VERIFY_PARAM_set1
                 U X509_VERIFY_PARAM_set1_host
                 U X509_VERIFY_PARAM_set_auth_level
                 U X509_VERIFY_PARAM_set_depth
                 U X509_VERIFY_PARAM_set_hostflags
                 U X509_VERIFY_PARAM_set_purpose
                 U X509_VERIFY_PARAM_set_trust
                 U ZINT32_it
                 U ZINT64_it
                 U ZUINT32_it
                 U ZUINT64_it
```

引用boringssl OpenSSL_add_all_algorithms函数，不是openssl

grpc_cpp_plugin.exe
grpc_csharp_plugin.exe
grpc_objective_c_plugin.exe
grpc_python_plugin.exe
grpc_ruby_plugin.exe

protobuffer的编译方法在文档 third_party\protobuf\cmake\readme.md

boringssl
openssl



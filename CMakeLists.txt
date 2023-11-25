cmake_minimum_required(VERSION 3.0)
project(hypre)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(hypre
        test/hypre_test.cpp
        schemes/hypre/hypre_impl.cpp
        schemes/hypre/hypre.cpp
        utils/utils.cpp
        curves/curve_param.cpp
        data_structure/access_structure.cpp data_structure/binary_tree.cpp data_structure/element_t_matrix.cpp
        data_structure/element_t_vector.cpp data_structure/multiway_tree.cpp data_structure/num_vector.cpp
        extend_math_operation/extend_math_operation.cpp
        message_serialization/element_bytes.cpp message_serialization/format_string_bytes.cpp message_serialization/message_serialization.cpp
        policy_generation/policy_generation.cpp
        policy_resolution/policy_resolution.cpp
        scheme_structure/abe_ciphertext.cpp scheme_structure/abe_key.cpp scheme_structure/Ciphertext.cpp
        scheme_structure/Ciphertext_CET.cpp scheme_structure/Ciphertext_DET.cpp scheme_structure/Ciphertext_HCET.cpp
        scheme_structure/Key.cpp scheme_structure/sar_kgc.cpp scheme_structure/sar_tree.cpp scheme_structure/SecretKey.cpp scheme_structure/Text.cpp
        symmetric_encryption/aes.cpp
        )

add_executable(hypre_param_test
        test/hypre_with_diff_params.cpp
        schemes/hypre/hypre_impl.cpp
        schemes/hypre/hypre.cpp
        utils/utils.cpp
        curves/curve_param.cpp
        data_structure/access_structure.cpp data_structure/binary_tree.cpp data_structure/element_t_matrix.cpp
        data_structure/element_t_vector.cpp data_structure/multiway_tree.cpp data_structure/num_vector.cpp
        extend_math_operation/extend_math_operation.cpp
        message_serialization/element_bytes.cpp message_serialization/format_string_bytes.cpp message_serialization/message_serialization.cpp
        policy_generation/policy_generation.cpp
        policy_resolution/policy_resolution.cpp
        scheme_structure/abe_ciphertext.cpp scheme_structure/abe_key.cpp scheme_structure/Ciphertext.cpp
        scheme_structure/Ciphertext_CET.cpp scheme_structure/Ciphertext_DET.cpp scheme_structure/Ciphertext_HCET.cpp
        scheme_structure/Key.cpp scheme_structure/sar_kgc.cpp scheme_structure/sar_tree.cpp scheme_structure/SecretKey.cpp scheme_structure/Text.cpp
        symmetric_encryption/aes.cpp
        )

# ----------------------- cJSON & OpenSSL & gmp -----------------------
find_package(cJSON REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(hypre "/lib/x86_64-linux-gnu/libgmpxx.a" "/lib/x86_64-linux-gnu/libgmp.a" OpenSSL::Crypto cjson pbc)
target_link_libraries(hypre_param_test "/lib/x86_64-linux-gnu/libgmpxx.a" "/lib/x86_64-linux-gnu/libgmp.a" OpenSSL::Crypto cjson pbc)
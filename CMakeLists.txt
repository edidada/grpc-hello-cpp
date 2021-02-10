cmake_minimum_required(VERSION 3.12)
project(grpc-hello-cpp)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

#execute_process(COMMAND sh ../script/mkdir.sh)
execute_process(COMMAND sh ../script/protoc.sh)

set(PROTO_PATH "${CMAKE_SOURCE_DIR}/protos")
set(HELLOWORLD_PROTO "${PROTO_PATH}/helloworld.proto")
set(GENERATED_PROTOBUF_PATH "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${GENERATED_PROTOBUF_PATH})

set(HELLOWORLD_PB_CPP_FILE "${GENERATED_PROTOBUF_PATH}/helloworld.pb.cc")
set(HELLOWORLD_PB_H_FILE "${GENERATED_PROTOBUF_PATH}/helloworld.pb.h")
set(HELLOWORLD_GRPC_PB_CPP_FILE "${GENERATED_PROTOBUF_PATH}/helloworld.grpc.pb.cc")
set(HELLOWORLD_GRPC_PB_H_FILE "${GENERATED_PROTOBUF_PATH}/helloworld.grpc.pb.h")


add_custom_command(
        OUTPUT "${HELLOWORLD_PB_H_FILE}"
        "${HELLOWORLD_PB_CPP_FILE}"
        "${HELLOWORLD_GRPC_PB_H_FILE}"
        "${HELLOWORLD_GRPC_PB_CPP_FILE}"
        COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
        ARGS "--proto_path=${PROTO_PATH}"
        "--cpp_out=${GENERATED_PROTOBUF_PATH}"
        "${HELLOWORLD_PROTO}"
        COMMAND ${PROTOBUF_PROTOC_EXECUTABLE}
        ARGS "--proto_path=${PROTO_PATH}"
        "--grpc_out=${GENERATED_PROTOBUF_PATH}"
        "--plugin=protoc-gen-grpc=/usr/local/bin/GRPC_CPP_PLUGIN"
        "${HELLOWORLD_PROTO}"
)
set(GENERATED_PROTOBUF_FILES ${HELLOWORLD_PB_H_FILE} ${HELLOWORLD_PB_CPP_FILE}
        ${HELLOWORLD_GRPC_PB_H_FILE} ${HELLOWORLD_GRPC_PB_CPP_FILE})
add_executable(greeter_server greeter_server.cc ${GENERATED_PROTOBUF_FILES})
add_executable(greeter_client greeter_client.cc ${GENERATED_PROTOBUF_FILES})
add_executable(greeter_async_server async/greeter_async_server.cc ${GENERATED_PROTOBUF_FILES})
add_executable(greeter_async_client async/greeter_async_client.cc ${GENERATED_PROTOBUF_FILES})

find_package(gRPC CONFIG REQUIRED)
# Note: 8 target(s) were omitted.
target_link_libraries(greeter_server gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts)
#target_link_libraries(greeter_client PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc_cronet)
#target_link_libraries(greeter_async_server PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc_cronet)
#target_link_libraries(greeter_async_client PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc_cronet)

#find_package(modules CONFIG REQUIRED)
#target_link_libraries(greeter_server PRIVATE re2::re2 c-ares::cares)
